{-# LANGUAGE OverloadedStrings #-}
module Argon2 where

import Test.Tasty
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Data.Password.Argon2

import Internal


testArgon2 :: TestTree
testArgon2 = testGroup "Argon2"
  [ referenceTest
  , testCorrectPassword "Argon2 (hashPassword)" hashFast checkPassword
  , testIncorrectPassword "Argon2 (hashPassword) fail" hashFast checkPassword
  , testWithSalt "Argon2 (hashPasswordWithSalt)"
                 (hashPasswordWithSalt fastParams)
                 checkPassword
  , testWithParams "Argon2 (Argon2i)" $ fastParams{ argon2Variant = Argon2i }
  , testWithParams "Argon2 (Argon2d)" $ fastParams{ argon2Variant = Argon2d }
  , paddingTests
  ]
  where
    testWithParams s params =
      testWithSalt s (hashPasswordWithSalt params) checkPassword
    hashFast = hashPasswordWithParams fastParams
    fastParams =
      defaultParams{
        argon2MemoryCost = 2 ^ (8 :: Int),
        argon2TimeCost = 1
      }

paddingTests :: TestTree
paddingTests = testGroup "Padding"
    [ testCase "with padding" $
        assertBool "Bad hash" $ checkPassword pass hashWithPadding == PasswordCheckSuccess
    , testCase "without padding" $
        assertBool "Bad hash" $ checkPassword pass hashWithoutPadding == PasswordCheckSuccess
    ]

pass :: Password
pass = "foobar"

-- Hashed password ("foobar") with salt ("abcdefghijklmnop")
hashWithPadding, hashWithoutPadding :: PasswordHash Argon2
hashWithPadding    = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA==$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o="
hashWithoutPadding = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o"

-- Reference check using the Command-line Utility output example
-- from: https://github.com/P-H-C/phc-winner-argon2
referenceTest :: TestTree
referenceTest = testCase "PHC Argon2 reference" $
    assertEqual "output hash is wrong" expected $
        hashPasswordWithSalt params salt pwd
  where
    expected = PasswordHash "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
    salt = Salt "somesalt"
    pwd = mkPassword "password"
    params = defaultParams {
        argon2Variant = Argon2i,
        argon2Parallelism = 4,
        argon2OutputLength = 24
    }
