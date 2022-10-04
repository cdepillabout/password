import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.Runners (NumThreads(..))

import Data.Password.Types

import Argon2 (testArgon2)
import Bcrypt (testBcrypt)
import PBKDF2 (testPBKDF2)
import Scrypt (testScrypt)
import Validate (testValidate)

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
