{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()
import Web.HttpApiData (FromHttpApiData(..))

import Data.Password.Types (Password, PasswordHash(..), unsafeShowPassword)
import Data.Password.HttpApiData()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ fromHttpApiDataTest
  ]

fromHttpApiDataTest :: TestTree
fromHttpApiDataTest = testCase "Password (FromHttpApiData)" $
    assertEqual "password doesn't match" (Right testPassword) $
      unsafeShowPassword <$> parseUrlPiece testPassword
  where
    testPassword = "passtest"
