module Bcrypt where

import Test.Tasty

import Data.Password.Bcrypt

import Internal (testCorrectPassword, testIncorrectPassword, testWithSalt)


testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testCorrectPassword "Bcrypt (hashPassword)" (hashPasswordWithParams 4) checkPassword
  , testIncorrectPassword "Bcrypt (hashPassword) fail" (hashPasswordWithParams 4) checkPassword
  , testWithSalt "Bcrypt (hashPasswordWithSalt)" (hashPasswordWithSalt 4) checkPassword
  ]
