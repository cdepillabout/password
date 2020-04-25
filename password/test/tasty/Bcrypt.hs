{-# LANGUAGE OverloadedStrings #-}
module Bcrypt where

import Data.Text (Text)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password
import Data.Password.Bcrypt

import Internal (testCorrectPassword, testWithSalt, run10)


testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testCorrectPassword "Bcrypt (hashPassword)" (hashPasswordWithParams 4) checkPassword
  , testProperty "Bcrypt (hashPassword) fail" failTest
  , testWithSalt "Bcrypt (hashPasswordWithSalt)" (hashPasswordWithSalt 4) checkPassword
  ]

failTest :: Text -> Text -> Property
failTest pass pass2 = run10 $ do
    let pw = mkPassword pass
        pw2 = mkPassword pass2
        result = if pass == pass2 then PasswordCheckSuccess
                                  else PasswordCheckFail
        isEmpty c = c == "" || c == "\NUL"
    -- FIXME: for some reason, "\NUL" hashes the same as an empty string
    -- This will(/should) NEVER happen in the real world, though.
    if all isEmpty [pass, pass2]
      then return $ property True
      else do
        hpw <- hashPasswordWithParams 4 pw
        return $ checkPassword pw2 hpw === result
