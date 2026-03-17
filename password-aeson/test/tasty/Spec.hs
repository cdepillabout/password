{-# LANGUAGE OverloadedStrings #-}

import Data.Aeson
import Data.Aeson.Types (parseMaybe)
import Data.Text (Text)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.QuickCheck (testProperty, (===))
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (Password, unsafeShowPassword)
import Data.Password.Aeson ()


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
aesonTest =
  testProperty "Password (Aeson)" $ \pwd ->
    Just pwd === (unsafeShowPassword . password <$> parseIt pwd)
  where
    parseIt pwd =
      parseMaybe parseJSON $
        object
          [ "name" .= String "testname"
          , "password" .= String pwd
          ]
