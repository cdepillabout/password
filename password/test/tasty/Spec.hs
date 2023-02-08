{-# LANGUAGE CPP #-}

import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.Runners (NumThreads(..))

import Data.Password.Types

#ifdef CABAL_FLAG_argon2
import Argon2 (testArgon2)
#endif
#ifdef CABAL_FLAG_bcrypt
import Bcrypt (testBcrypt)
#endif
#ifdef CABAL_FLAG_pbkdf2
import PBKDF2 (testPBKDF2)
#endif
#ifdef CABAL_FLAG_scrypt
import Scrypt (testScrypt)
#endif
import Validate (testValidate)

main :: IO ()
main = defaultMain $ localOption (NumThreads 1) $
  testGroup "Password"
    [ testProperty "Password" $ \pass ->
        unsafeShowPassword (mkPassword pass) === pass
#ifdef CABAL_FLAG_argon2
    , testArgon2
#endif
#ifdef CABAL_FLAG_bcrypt
    , testBcrypt
#endif
#ifdef CABAL_FLAG_pbkdf2
    , testPBKDF2
#endif
#ifdef CABAL_FLAG_scrypt
    , testScrypt
#endif
    , testValidate
    ]
