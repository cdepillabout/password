{-# LANGUAGE OverloadedStrings #-}

import Database.Persist.Class (PersistField (..))
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.QuickCheck (testProperty, (===))
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (PasswordHash (..))
import Data.Password.Persistent()


main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ persistTest
  ]

persistTest :: TestTree
persistTest = testProperty "PasswordHash (PersistField)" $ \pass ->
    let pwd = PasswordHash pass
    in fromPersistValue (toPersistValue pwd) === Right pwd
