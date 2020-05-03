module Argon2 where

import Test.Tasty
import Test.QuickCheck.Instances.Text ()

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
