{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TypeApplications #-}
module PBKDF2 where

import Crypto.Hash.Algorithms as Crypto (HashAlgorithm, SHA1(..), SHA256(..), SHA512(..))
import Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteString (ByteString)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.ByteString ()
import Test.QuickCheck.Instances.Text ()

import Data.Password.PBKDF2

import Internal


testPBKDF2 :: TestTree
testPBKDF2 = testGroup "PBKDF2"
  [ testCorrectPassword "PBKDF2 (hashPassword)" hashPassword checkPassword
  , testIncorrectPassword "PBKDF2 (hashPassword) fail" hashPassword checkPassword
  , testWithSalt "PBKDF2 (hashPasswordWithSalt)"
                 (hashPasswordWithSalt defaultParams)
                 checkPassword
  , let params = defaultParams{ pbkdf2Algorithm = PBKDF2_MD5, pbkdf2Iterations = 5000 }
    in testCorrectPassword "PBKDF2 (md5)" (hashPasswordWithParams params) checkPassword
  , testCorrectPassword "PBKDF2 (sha1)"
                        (hashPasswordWithParams
                            defaultParams{pbkdf2Algorithm = PBKDF2_SHA1})
                        checkPassword
  , testCorrectPassword "PBKDF2 (sha256)"
                        (hashPasswordWithParams
                            defaultParams{pbkdf2Algorithm = PBKDF2_SHA256})
                        checkPassword
  , testFast Crypto.SHA1 20 PBKDF2.fastPBKDF2_SHA1
  , testFast Crypto.SHA256 32 PBKDF2.fastPBKDF2_SHA256
  , testFast Crypto.SHA512 64 PBKDF2.fastPBKDF2_SHA512
  ]

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
    PBKDF2.iterCounts = 25 * 1000,
    PBKDF2.outputLength = i
  }
