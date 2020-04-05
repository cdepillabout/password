import Test.Tasty
import Test.Tasty.QuickCheck

import Data.Password

import Argon2
import Bcrypt
import PBKDF2
import Scrypt

main :: IO ()
main = defaultMain $ localOption (NumThreads 1) $
  testGroup "Password"
    [ testProperty "Password" $ \pass ->
        unsafeShowPasswordText (mkPassword pass) === pass
    , testArgon2
    , testBcrypt
    , testPBKDF2
    , testScrypt
    ]
