{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}

module Data.Password
  (
    -- * Plaintext Password
    Pass(..)
    -- * Hashed Password
  , PassHash(..)
  , Salt(..)
    -- * Functions for Hashing Plaintext Passwords
  , hashPass
  , hashPassWithSalt
  , newSalt
    -- * Functions for Checking Plaintext Passwords Against Hashed Passwords
  , checkPass
  , PassCheck
  , -- * Setup for doctests.
    -- $setup
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Scrypt (EncryptedPass(..), Salt(..), defaultParams, encryptPass,
                      newSalt, verifyPass')
import qualified Crypto.Scrypt as Scrypt
import Data.String (IsString)
import Data.Text (Text)
import Data.Text.Encoding (decodeUtf8With, encodeUtf8)
import Data.Text.Encoding.Error (lenientDecode)

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), vector)
-- >>> import Test.QuickCheck.Instances.ByteString ()
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- 'Arbitrary' instances for types exported from this library.
--
-- >>> instance Arbitrary Salt where arbitrary = Salt . pack <$> vector 32
-- >>> instance Arbitrary Pass where arbitrary = fmap Pass arbitrary
-- >>> instance Arbitrary PassHash where arbitrary = hashPassWithSalt <$> arbitrary <*> arbitrary
--
-- 'Arbitrary' instances for types exported from "Crypto.Scrypt".
--
-- >>> instance Arbitrary Scrypt.Pass where arbitrary = fmap Scrypt.Pass arbitrary
-- >>> instance Arbitrary EncryptedPass where arbitrary = encryptPass defaultParams <$> arbitrary <*> arbitrary

newtype Pass = Pass
  { unPass :: Text
  } deriving (Eq, IsString, Ord, Read, Show)

newtype PassHash = PassHash
  { unPassHash :: Text
  } deriving (Eq, Ord, Read, Show)

-- | Convert an "Crypto.Scrypt".'Scrypt.Pass' to our 'Pass' type.
--
-- >>> passToScryptPass $ Pass "foobar"
-- Pass {getPass = "foobar"}
passToScryptPass :: Pass -> Scrypt.Pass
passToScryptPass (Pass pass) = Scrypt.Pass $ encodeUtf8 pass

-- Convert our 'Pass' type to an "Crypto.Scrypt".'Script.Pass'.
--
-- Opposite of 'passToScryptPass'.
--
-- >>> scryptPassToPass $ Scrypt.Pass "foobar"
-- Pass {getPass = "foobar"}
-- scryptPassToPass :: Scrypt.Pass -> Pass
-- scryptPassToPass (Scrypt.Pass pass) = Pass $ decodeUtf8With lenientDecode pass

-- | Convert an "Crypto.Scrypt".'EncryptedPass' to our 'PassHash' type.
--
-- This is the opposite of 'passHashToScryptEncryptedPass'.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = Scrypt.Pass "foobar"
-- >>> let encryptedPass = encryptPass defaultParams salt pass
-- >>> encryptedPass
-- EncryptedPass {getEncryptedPass = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
-- >>> scryptEncryptedPassToPassHash encryptedPass
-- PassHash {unPassHash = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
--
-- prop> scryptEncryptedPassToPassHash (passHashToScryptEncryptedPass passHash) == passHash
scryptEncryptedPassToPassHash :: EncryptedPass -> PassHash
scryptEncryptedPassToPassHash (EncryptedPass encPass) =
  PassHash $ decodeUtf8With lenientDecode encPass

-- | Convert out 'PassHash' type to "Crypto.Scrypt".'EncryptedPass'.
--
-- This is the opposite of 'scryptEncryptedPassToPassHash'.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = Scrypt.Pass "foobar"
-- >>> let encryptedPass = encryptPass defaultParams salt pass
-- >>> encryptedPass
-- EncryptedPass {getEncryptedPass = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
-- >>> scryptEncryptedPassToPassHash encryptedPass
-- PassHash {unPassHash = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
--
-- prop> passHashToScryptEncryptedPass (scryptEncryptedPassToPassHash encPass) == encPass
passHashToScryptEncryptedPass :: PassHash -> EncryptedPass
passHashToScryptEncryptedPass (PassHash passHash) =
  EncryptedPass $ encodeUtf8 passHash

-- | Just like 'hashPassWithSalt', but generate a new 'Salt' everytime with a
-- call to 'newSalt'.
--
-- >>> hashPass (Pass "foobar")
-- PassHash {unPassHash = "14|8|1|...|..."}
hashPass :: MonadIO m => Pass -> m PassHash
hashPass pass = do
  salt <- liftIO newSalt
  pure $ hashPassWithSalt pass salt

-- | Hash a password with the given 'Salt'.
--
-- The resulting 'PassHash' has the parameters used to hash it, as well as the
-- 'Salt' appended to it, separated by @|@.
--
-- The input 'Salt' and resulting 'PassHash' are both byte-64 encoded.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> hashPassWithSalt (Pass "foobar") salt
-- PassHash {unPassHash = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'.  'hashPass'
-- generates a new 'Salt' everytime it is called.)
hashPassWithSalt :: Pass -> Salt -> PassHash
hashPassWithSalt pass salt =
  scryptEncryptedPassToPassHash $
    encryptPass defaultParams salt (passToScryptPass pass)

data PassCheck = PassCheckSucc | PassCheckFail deriving (Eq, Read, Show)

-- | Check a 'Pass' against a 'PassHash'.
--
-- Returns 'PassCheckSucc' on success.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = Pass "foobar"
-- >>> let passHash = hashPassWithSalt pass salt
-- >>> checkPass pass passHash
-- PassCheckSucc
--
-- Returns 'PassCheckFail' If an incorrect 'Pass' or 'PassHash' is used.
--
-- >>> let badpass = Pass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> let correctPassHash = hashPassWithSalt (Pass "foobar") salt in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash -> PassCheck
checkPass pass passHash =
  if verifyPass' (passToScryptPass pass) (passHashToScryptEncryptedPass passHash)
  then PassCheckSucc
  else PassCheckFail

-- TODO: Create code for checking that plaintext passwords conform to some sort of
-- password policy.

-- data PassPolicy = PassPolicy
--   { passPolicyLength :: Int
--   , passPolicyCharReqs :: [PolicyCharReq]
--   , passPolicyCharSet :: PolicyCharSet
--   }

-- -- | Character requirements for a password policy.
-- data PolicyCharReq
--   = PolicyCharReqUpper Int
--   -- ^ A password requires at least 'Int' upper-case characters.
--   | PolicyCharReqLower Int
--   -- ^ A password requires at least 'Int' lower-case characters.
--   | PolicyCharReqSpecial Int
--   -- ^ A password requires at least 'Int' special characters

-- data PolicyCharSet = PolicyCharSetAscii
