module Argon2 where

import Test.Tasty
import Test.QuickCheck.Instances.Text ()

import Data.Password.Argon2

import Internal


testArgon2 :: TestTree
testArgon2 = testGroup "Argon2"
  [ testCorrectPassword "Argon2 (hashPassword)" hashPassword checkPassword
  , testIncorrectPassword "Argon2 (hashPassword) fail" hashPassword checkPassword
  , testWithSalt "Argon2 (hashPasswordWithSalt)"
                 (hashPasswordWithSalt defaultParams)
                 checkPassword
  , testWithParams "Argon2 (Argon2i)" $ defaultParams {argon2Variant = Argon2i}
  , testWithParams "Argon2 (Argon2d)" $ defaultParams {argon2Variant = Argon2d}
  ]
  where
    testWithParams s params =
      testWithSalt s (hashPasswordWithSalt params) checkPassword
