{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module PBKDF2 where

import Crypto.Hash.Algorithms as Crypto (HashAlgorithm, SHA1(..), SHA256(..), SHA512(..))
import Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteString (ByteString)
import Data.ByteString.Lazy (fromStrict)
#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text.Encoding (encodeUtf8)
import Test.Tasty
import Test.Tasty.Golden (goldenVsString)
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.ByteString ()
import Test.QuickCheck.Instances.Text ()

import Data.Password.PBKDF2

import Internal

testPBKDF2 :: TestTree
testPBKDF2 = testGroup "PBKDF2"
  [ testIt "PBKDF2 (hashPassword)" testParams -- This is PBKDF2_SHA512
  , testIncorrectPassword
      "PBKDF2 (hashPassword) fail"
      (hashPasswordWithParams testParams)
      checkPassword
  , testWithSalt
      "PBKDF2 (hashPasswordWithSalt)"
      (hashPasswordWithSalt testParams)
      checkPassword
      extractParams
      testParams
  , testIt "PBKDF2 (md5)"    (defaultParams{ pbkdf2Algorithm = PBKDF2_MD5, pbkdf2Iterations = 1000, pbkdf2OutputLength = 16 })
  , testIt "PBKDF2 (sha1)"   (testParams{ pbkdf2Algorithm = PBKDF2_SHA1, pbkdf2OutputLength = 20 })
  , testIt "PBKDF2 (sha256)" (testParams{ pbkdf2Algorithm = PBKDF2_SHA256, pbkdf2OutputLength = 32 })
  , testFast Crypto.SHA1   20 PBKDF2.fastPBKDF2_SHA1
  , testFast Crypto.SHA256 32 PBKDF2.fastPBKDF2_SHA256
  , testFast Crypto.SHA512 64 PBKDF2.fastPBKDF2_SHA512
  -- Check to see if a hash with "pbkdf2:" prefixed also works
  , testCorrectPassword
      "PBKDF2 (pbkdf2:sha-...)"
      (hashPasswordWithParams testParams)
      (\pass (PasswordHash hash) -> checkPassword pass . PasswordHash $ "pbkdf2:" <> hash)
      extractParams
      testParams
  , testGolden
  ]
  where
    testIt s params = testCorrectPassword s (hashPasswordWithParams params) checkPassword extractParams params
    testParams = defaultParams{ pbkdf2Iterations = 4 * 1000 }

testFast :: (HashAlgorithm a, Show a)
         => a
         -> Int
         -> (Parameters -> ByteString -> ByteString -> ByteString)
         -> TestTree
testFast alg i f = testProperty s $ \pass salt ->
    f params pass salt === PBKDF2.generate (PBKDF2.prfHMAC alg) params pass salt
  where
    params = cryptoParams i
    s = sAlg ++ " HMAC == fast_" ++ sAlg
    sAlg = show alg

cryptoParams :: Int -> PBKDF2.Parameters
cryptoParams i = PBKDF2.Parameters {
    PBKDF2.iterCounts = 2000,
    PBKDF2.outputLength = i
  }

testGolden :: TestTree
testGolden = testGroup "Golden tests"
    [ go "defaultParams" "PBKDF2_defaultParams" defaultParams "somesalt42"
    , go "algorithm = MD5" "PBKDF2_algorithmMD5" defaultParams{pbkdf2Algorithm = PBKDF2_MD5} "somesalt42"
    , go "output length = 16" "PBKDF2_outputLength16" defaultParams{pbkdf2OutputLength = 16} "somesalt42"
    , go "iterCounts = 1000" "PBKDF2_iterCounts1000" defaultParams{pbkdf2Iterations = 1000} "somesalt42"
    , go "other salt" "PBKDF2_otherSalt" defaultParams "somesalt0"
    ]
  where go testName fileName params salt =
          goldenVsString
            testName
            ("test/golden/" <> fileName <> ".golden")
            (return $ fromStrict $ encodeUtf8 $ unPasswordHash $ hashPasswordWithSalt params (Salt salt) $ mkPassword "password")
