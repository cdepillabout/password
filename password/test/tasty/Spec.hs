import Test.Tasty
import Test.Tasty.QuickCheck

import Data.Password

import Argon2
import Bcrypt
import PBKDF2
import Scrypt

main :: IO ()
main = defaultMain $ testGroup "Password"
  [ testProperty "Pass" $ \pass ->
      unsafeShowPasswordText (mkPass pass) === pass
  , testArgon2
  , testBcrypt
  , testPBKDF2
  , testScrypt
  ]
