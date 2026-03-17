{-# LANGUAGE OverloadedStrings #-}

import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.QuickCheck (testProperty, (===))
import Test.QuickCheck.Instances ()
import Web.HttpApiData (FromHttpApiData (..))

import Data.Password.Types (unsafeShowPassword)
import Data.Password.HttpApiData ()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ fromHttpApiDataTest
  ]

fromHttpApiDataTest :: TestTree
fromHttpApiDataTest =
    testProperty "Password (FromHttpApiData)" $ \pw ->
        (Right pw) === (unsafeShowPassword <$> parseUrlPiece pw)
