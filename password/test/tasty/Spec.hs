import Test.Tasty
import Test.Tasty.QuickCheck

import Data.Password
import Scrypt

main :: IO ()
main = defaultMain $ testGroup "Password"
  [ testProperty "Pass" $ \pass ->
      unsafeShowPasswordText (mkPass pass) === pass
  , testScrypt
  ]
