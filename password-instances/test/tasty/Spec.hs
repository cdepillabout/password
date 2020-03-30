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

import Data.Password (Pass, PassHash(..), unsafeShowPasswordText)
import Data.Password.Instances()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ aesonTest
  , fromHttpApiDataTest
  , persistTest
  ]

data TestUser = TestUser {
  name :: Text,
  password :: Pass
} deriving (Show)

instance FromJSON TestUser where
  parseJSON = withObject "TestUser" $ \o ->
    TestUser <$> o .: "name" <*> o .: "password"


aesonTest :: TestTree
aesonTest = testCase "Pass (Aeson)" $
    assertEqual "password doesn't match" (Just testPass) $
      unsafeShowPasswordText . password <$> parseMaybe parseJSON testUser
  where
    testPass = "testpass"
    testUser = object
      [ "name" .= String "testname"
      , "password" .= String testPass
      ]

fromHttpApiDataTest :: TestTree
fromHttpApiDataTest = testCase "Pass (FromHttpApiData)" $
    assertEqual "password doesn't match" (Right testPass) $
      unsafeShowPasswordText <$> parseUrlPiece testPass
  where
    testPass = "passtest"

persistTest :: TestTree
persistTest = testProperty "PassHash (PersistField)" $ \pass ->
    let pwd = PassHash pass
    in fromPersistValue (toPersistValue pwd) === Right pwd
