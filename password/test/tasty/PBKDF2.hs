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
  [ testCorrectPass "PBKDF2 (hashPass)" hashPass checkPass
  , testIncorrectPass "PBKDF2 (hashPass) fail" hashPass checkPass
  , testWithSalt "PBKDF2 (hashPassWithSalt)" (hashPassWithSalt defaultParams) checkPass
  , let params = defaultParams{ pbkdf2Algorithm = PBKDF2_MD5, pbkdf2Iterations = 5000 }
    in testCorrectPass "PBKDF2 (md5)" (hashPassWithParams params) checkPass
  , testCorrectPass "PBKDF2 (sha1)" (hashPassWithParams defaultParams{pbkdf2Algorithm = PBKDF2_SHA1}) checkPass
  , testCorrectPass "PBKDF2 (sha256)" (hashPassWithParams defaultParams{pbkdf2Algorithm = PBKDF2_SHA256}) checkPass
  , testFast Crypto.SHA1 20 PBKDF2.fastPBKDF2_SHA1
  , testFast Crypto.SHA256 32 PBKDF2.fastPBKDF2_SHA256
  , testFast Crypto.SHA512 64 PBKDF2.fastPBKDF2_SHA512
  ]

testFast :: (HashAlgorithm a, Show a) => a -> Int -> (Parameters -> ByteString -> ByteString -> ByteString) -> TestTree
testFast alg i f = testProperty s $ \pass salt -> run10 $
    return $ f params pass salt === PBKDF2.generate (PBKDF2.prfHMAC alg) params pass salt
  where
    params = cryptoParams i
    s = sAlg ++ " HMAC == fast_" ++ sAlg
    sAlg = show alg

cryptoParams :: Int -> PBKDF2.Parameters
cryptoParams i = PBKDF2.Parameters {
    PBKDF2.iterCounts = 25 * 1000,
    PBKDF2.outputLength = i
  }
