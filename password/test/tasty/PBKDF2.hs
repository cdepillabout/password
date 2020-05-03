{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module PBKDF2 where

import Crypto.Hash.Algorithms as Crypto (HashAlgorithm, SHA1(..), SHA256(..), SHA512(..))
import Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteString (ByteString)
#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.ByteString ()
import Test.QuickCheck.Instances.Text ()

import Data.Password.PBKDF2

import Internal

_10k :: Num a => a
_10k = 10 * 1000

testPBKDF2 :: TestTree
testPBKDF2 = testGroup "PBKDF2"
  [ testIt "PBKDF2 (hashPassword)" $ _10k defaultParams -- This is PBKDF2_SHA512
  , testIncorrectPassword_
      "PBKDF2 (hashPassword) fail"
      (hashPasswordWithParams $ _10k defaultParams)
      checkPassword
  , testWithSalt
      "PBKDF2 (hashPasswordWithSalt)"
      (hashPasswordWithSalt $ _10k defaultParams)
      checkPassword
  , testIt "PBKDF2 (md5)"    (defaultParams{ pbkdf2Algorithm = PBKDF2_MD5, pbkdf2Iterations = 5000 })
  , testIt "PBKDF2 (sha1)"   (_10k defaultParams{ pbkdf2Algorithm = PBKDF2_SHA1 })
  , testIt "PBKDF2 (sha256)" (_10k defaultParams{ pbkdf2Algorithm = PBKDF2_SHA256 })
  , testFast Crypto.SHA1   20 PBKDF2.fastPBKDF2_SHA1
  , testFast Crypto.SHA256 32 PBKDF2.fastPBKDF2_SHA256
  , testFast Crypto.SHA512 64 PBKDF2.fastPBKDF2_SHA512
  -- Check to see if a hash with "pbkdf2:" prefixed also works
  , testCorrectPassword
      "PBKDF2 (pbkdf2:sha-...)"
      (hashPasswordWithParams $ _10k defaultParams)
      (\pass (PasswordHash hash) -> checkPassword pass . PasswordHash $ "pbkdf2:" <> hash)
  ]
  where
    testIt s params = testCorrectPassword s (hashPasswordWithParams params) checkPassword
    _10k params = params{ pbkdf2Iterations = 10 * 1000 }

testFast :: (HashAlgorithm a, Show a)
         => a
         -> Int
         -> (Parameters -> ByteString -> ByteString -> ByteString)
         -> TestTree
testFast alg i f = testProperty s $ \pass salt -> run10 $
    return $ f params pass salt ===
             PBKDF2.generate (PBKDF2.prfHMAC alg) params pass salt
  where
    params = cryptoParams i
    s = sAlg ++ " HMAC == fast_" ++ sAlg
    sAlg = show alg

cryptoParams :: Int -> PBKDF2.Parameters
cryptoParams i = PBKDF2.Parameters {
    PBKDF2.iterCounts = 5000,
    PBKDF2.outputLength = i
  }
