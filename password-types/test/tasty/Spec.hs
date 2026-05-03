module Main where

import Data.String (fromString)
import Data.Text (pack)
import Data.Text.Encoding (encodeUtf8)
import Test.QuickCheck.Instances ()
import Test.Tasty (defaultMain, testGroup)
import Test.Tasty.QuickCheck ((===), testProperty)

import Data.Password.Types (
    PasswordHash (..),
    constEquals,
    mkPassword,
    unsafeShowPassword,
 )

main :: IO ()
main = defaultMain $
  testGroup "Password"
    [ testProperty "mkPassword <-> unsafeShowPassword" $ \pass ->
        unsafeShowPassword (mkPassword pass) === pass
    , testProperty "Password always prints **PASSWORD**" $ \pass ->
        show (mkPassword pass) === "**PASSWORD**"
    , testProperty "fromString works" $ \pass ->
        unsafeShowPassword (fromString pass) === pack pass
    , testProperty "constEquals works identical to '=='" $ \t1 t2 ->
        let b1 = encodeUtf8 t1
            b2 = encodeUtf8 t2
         in (b1 `constEquals` b2) == (b1 == b2) 
    , testProperty "constEquals is True on the same input" $ \t1 ->
        let b1 = encodeUtf8 t1
         in b1 `constEquals` b1
    , testProperty "comparing 'PasswordHash'es works" $ \t1 ->
        PasswordHash t1 === PasswordHash t1
    ]
