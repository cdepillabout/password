{-# LANGUAGE OverloadedStrings #-}

import Data.Text (Text)
import Database.Persist.Class (PersistField(..))
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (Password, PasswordHash(..), unsafeShowPassword)
import Data.Password.Persistent()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ persistTest
  ]

data TestUser = TestUser {
  name :: Text,
  password :: Password
} deriving (Show)

persistTest :: TestTree
persistTest = testProperty "PasswordHash (PersistField)" $ \pass ->
    let pwd = PasswordHash pass
    in fromPersistValue (toPersistValue pwd) === Right pwd
