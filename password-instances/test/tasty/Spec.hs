{-# LANGUAGE OverloadedStrings #-}

import Data.Aeson
import Data.Aeson.Types (parseMaybe)
import Data.Text (Text)
import Database.Persist.Class (PersistField(..))
import Test.Tasty
import Test.Tasty.HUnit
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()
import Web.HttpApiData (FromHttpApiData(..))

import Data.Password (Password, PasswordHash(..), unsafeShowPasswordText)
import Data.Password.Instances()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ aesonTest
  , fromHttpApiDataTest
  , persistTest
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
      unsafeShowPasswordText . password <$> parseMaybe parseJSON testUser
  where
    testPassword = "testpass"
    testUser = object
      [ "name" .= String "testname"
      , "password" .= String testPassword
      ]

fromHttpApiDataTest :: TestTree
fromHttpApiDataTest = testCase "Password (FromHttpApiData)" $
    assertEqual "password doesn't match" (Right testPassword) $
      unsafeShowPasswordText <$> parseUrlPiece testPassword
  where
    testPassword = "passtest"

persistTest :: TestTree
persistTest = testProperty "PasswordHash (PersistField)" $ \pass ->
    let pwd = PasswordHash pass
    in fromPersistValue (toPersistValue pwd) === Right pwd
