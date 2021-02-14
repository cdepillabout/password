{-# LANGUAGE OverloadedStrings #-}
module Argon2 where

import Test.Tasty
import Test.Tasty.HUnit (assertBool, testCase)

import Data.Password.Argon2

import Internal


testArgon2 :: TestTree
testArgon2 = testGroup "Argon2"
  [ testCorrectPassword "Argon2 (hashPassword)" hashFast checkPassword
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
        assertBool "Bad hash" $ checkPassword pass testHash1 == PasswordCheckSuccess
    , testCase "without padding" $
        assertBool "Bad hash" $ checkPassword pass testHash2 == PasswordCheckSuccess
    ]

pass :: Password
pass = "foobar"

-- Hashed password ("foobar") with salt ("abcdefghijklmnop")
testHash1, testHash2 :: PasswordHash Argon2
testHash1 = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA==$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o="
testHash2 = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o"
