module Argon2 where

import Test.Tasty
-- import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Argon2

import Internal


testArgon2 :: TestTree
testArgon2 = testGroup "Argon2"
  [ testCorrectPass "Argon2 (hashPass)" hashPass checkPass
  , testIncorrectPass "Argon2 (hashPass) fail" hashPass checkPass
  , testWithSalt "Argon2 (hashPassWithSalt)" (hashPassWithSalt defaultParams) checkPass
  , testWithParams "Argon2 (Argon2i)" $ defaultParams {argon2Variant = Argon2i}
  , testWithParams "Argon2 (Argon2d)" $ defaultParams {argon2Variant = Argon2d}
  ]
  where
    testWithParams s params = testWithSalt s (hashPassWithSalt params) checkPass
