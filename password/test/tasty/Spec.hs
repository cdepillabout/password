import Test.Tasty
import Test.Tasty.QuickCheck

import Data.Password

import Argon2
import Bcrypt
import Scrypt

main :: IO ()
main = defaultMain $ testGroup "Password"
  [ testProperty "Pass" $ \pass ->
      unsafeShowPasswordText (mkPass pass) === pass
  , testArgon2
  , testBcrypt
  , testScrypt
  ]
