import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.Runners (NumThreads(..))

import Data.Password

import Argon2
import Bcrypt
import PBKDF2
import Scrypt
import Validate

main :: IO ()
main = defaultMain $ localOption (NumThreads 1) $
  testGroup "Password"
    [ testProperty "Password" $ \pass ->
        unsafeShowPassword (mkPassword pass) === pass
    , testArgon2
    , testBcrypt
    , testPBKDF2
    , testScrypt
    , testValidate
    ]
