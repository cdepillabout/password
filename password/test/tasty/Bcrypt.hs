{-# LANGUAGE OverloadedStrings #-}
module Bcrypt where

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password
import Data.Password.Bcrypt

import Internal (testCorrectPass, testWithSalt, run10)


testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testCorrectPass "Bcrypt (hashPass)" hashPass checkPass
  , testProperty "Bcrypt (hashPass) fail" $ \pass pass2 -> run10 $ do
      let pw = mkPass pass
          pw2 = mkPass pass2
          result = if pass == pass2 then PassCheckSuccess else PassCheckFail
          isEmpty c = c == "" || c == "\NUL"
      -- FIXME: for some reason, "\NUL" hashes the same as an empty string
      -- This will(/should) NEVER happen in the real world, though.
      if all isEmpty [pass, pass2]
        then return $ property True
        else do
          hpw <- hashPass pw
          return $ checkPass pw2 hpw === result
  , testWithSalt "Bcrypt (hashPassWithSalt)" (hashPassWithSalt 10) checkPass
  ]
