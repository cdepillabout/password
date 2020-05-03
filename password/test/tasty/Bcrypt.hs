module Bcrypt where

import Data.Text (Text)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password
import Data.Password.Bcrypt

import Internal (testCorrectPassword, testIncorrectPassword_, testWithSalt)


testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testCorrectPassword "Bcrypt (hashPassword)" (hashPasswordWithParams 4) checkPassword
  , testIncorrectPassword_ "Bcrypt (hashPassword) fail" (hashPasswordWithParams 4) checkPassword
  , testWithSalt "Bcrypt (hashPasswordWithSalt)" (hashPasswordWithSalt 4) checkPassword
  ]
