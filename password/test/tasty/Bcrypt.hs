{-# LANGUAGE OverloadedStrings #-}
module Bcrypt where

import Data.Text (pack)
import Test.Tasty
import Test.Tasty.HUnit (testCase, assertEqual)

import Data.Password.Bcrypt

import Internal


testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testCorrectPassword "Bcrypt (hashPassword)" (hashPasswordWithParams 4) checkPassword extractParams 4
  , testCorrectPassword "Bcrypt (hashPassword 2)" (hashPasswordWithParams 5) checkPassword extractParams 5
  , testIncorrectPassword "Bcrypt (hashPassword) fail" (hashPasswordWithParams 4) checkPassword
  , testWithSalt "Bcrypt (hashPasswordWithSalt)" (hashPasswordWithSalt 4) checkPassword extractParams 4
  , testPassword "2b"
  , testPassword "2y"
  , testPassword "2a"
-- These apparently do not work.
--   , testPassword "2x"
--   , testPassword "2"
  ]

-- | Tests if the version does not matter for matching the hash.
testPassword :: String -> TestTree
testPassword s =
    testCase ("Bcrypt (can check " <> s <> ")") $
        let x = checkPassword "testtest" $ hash s
            msg = "unsuccessful hash check (" <> s <> ")"
         in assertEqual msg PasswordCheckSuccess x
  where
    hash v = PasswordHash $
        "$" <> pack v <> "$10$v0mMyoUN2ZvDqsJFPH6ft.FcpX67hdXhh7tWf8/hwWZrKZ8U2Phs6"
