module Main where

import Data.String (fromString)
import Data.Text (pack)
import Test.QuickCheck.Instances()
import Test.Tasty ( defaultMain, testGroup )
import Test.Tasty.QuickCheck ( (===), testProperty )

import Data.Password ( mkPassword, unsafeShowPassword )

main :: IO ()
main = defaultMain $
  testGroup "Password"
    [ testProperty "mkPassword <-> unsafeShowPassword" $ \pass ->
        unsafeShowPassword (mkPassword pass) === pass
    , testProperty "Password always prints **PASSWORD**" $ \pass ->
        show (mkPassword pass) === "**PASSWORD**"
    , testProperty "fromString works" $ \pass ->
        unsafeShowPassword (fromString pass) === pack pass
    ]
