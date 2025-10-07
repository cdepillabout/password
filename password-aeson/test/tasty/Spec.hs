{-# LANGUAGE OverloadedStrings #-}

import Data.Aeson
import Data.Aeson.Types (parseMaybe)
import Data.Text (Text)
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (Password, PasswordHash(..), unsafeShowPassword)
import Data.Password.Aeson()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ aesonTest
  ]

data TestUser = TestUser {
  name :: Text,
  password :: Password
} deriving (Show)

instance FromJSON TestUser where
  parseJSON = withObject "TestUser" $ \o ->
    TestUser <$> o .: "name" <*> o .: "password"


aesonTest :: TestTree
aesonTest = testCase "Password (Aeson)" $
    assertEqual "password doesn't match" (Just testPassword) $
      unsafeShowPassword . password <$> parseMaybe parseJSON testUser
  where
    testPassword = "testpass"
    testUser = object
      [ "name" .= String "testname"
      , "password" .= String testPassword
      ]
