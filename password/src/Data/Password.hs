{-# LANGUAGE GeneralizedNewtypeDeriving #-}

{-|
Module      : Data.Password
Copyright   : (c) Dennis Gosnell, 2019
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides an easy way for interacting with passwords from Haskell.
It provides the types 'Pass' and 'PassHash', which correspond to plain-text and
hashed passwords.

It also provides functions for hashing ('hashPass') and checking passwords
('checkPass').

The real benefit of this module is that there is a corresponding
<http://hackage.haskell.org/package/password-instances password-instances>
module that provides canonical typeclass instances for
'Pass' and 'PassHash' for many common typeclasses, like
<http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON FromJSON> from
<http://hackage.haskell.org/package/aeson aeson>,
<http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistField PersistField>
from
<http://hackage.haskell.org/package/persistent persistent>, etc.

See the <http://hackage.haskell.org/package/password-instances password-instances> module for more information.
-}

module Data.Password
  (
    -- * Plaintext Password
    Pass
  , mkPass
    -- * Hashed Password
  , PassHash(..)
  , Salt(..)
    -- * Functions for Hashing Plaintext Passwords
  , hashPass
  , hashPassWithSalt
  , newSalt
    -- * Functions for Checking Plaintext Passwords Against Hashed Passwords
  , checkPass
  , PassCheck(..)
    -- * Unsafe Debugging Functions for Showing a Password
  , unsafeShowPassword
  , unsafeShowPasswordText
  , -- * Setup for doctests.
    -- $setup
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Scrypt (EncryptedPass(..), Salt(..), defaultParams, encryptPass,
                      verifyPass')
import qualified Crypto.Scrypt as Scrypt
import Data.String (IsString(..))
import Data.Text (Text, unpack)
import Data.Text.Encoding (decodeUtf8With, encodeUtf8)
import Data.Text.Encoding.Error (lenientDecode)

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), Blind(Blind), vector)
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

-- | A plain-text password.
--
-- This represents a plain-text password that has /NOT/ been hashed.
--
-- You should be careful with 'Pass'. Make sure not to write it to logs or
-- store it in a database.
--
-- You can construct a 'Pass' by using the 'mkPass' function or as literal strings together with the
-- OverloadedStrings pragma (or manually, by using 'fromString' on a 'String').
-- Alternatively, you could also use some of the instances in the @password-instances@ library.
newtype Pass = Pass Text
  deriving (IsString)

-- | CAREFUL: 'Show'-ing a 'Pass' will always print @"**PASSWORD**"@
--
-- >>> show $ mkPass "hello"
-- "**PASSWORD**"
--
-- @since 1.0.0.0
instance Show Pass where
 show _ = "**PASSWORD**"

-- | Construct a 'Pass'
--
-- @since 1.0.0.0
mkPass :: Text -> Pass
mkPass = Pass

-- | This is an unsafe function that shows a password in plain-text.
--
-- >>> unsafeShowPasswordText $ mkPass "foobar"
-- "foobar"
--
-- You should generally not use this function.
unsafeShowPassword :: Pass -> String
unsafeShowPassword = unpack . unsafeShowPasswordText

-- | This is like 'unsafeShowPassword' but produces a 'Text' instead of a
-- 'String'.
unsafeShowPasswordText :: Pass -> Text
unsafeShowPasswordText (Pass pass) = pass

-- | A hashed password.
--
-- This represents a password that has been put through a hashing function.
-- The hashed password can be stored in a database.
newtype PassHash = PassHash
  { unPassHash :: Text
  } deriving (Eq, Ord, Read, Show)

-- | Convert an "Crypto.Scrypt".'Scrypt.Pass' to our 'Pass' type.
--
-- >>> passToScryptPass "foobar"
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
-- >>> hashPass $ mkPass "foobar"
-- PassHash {unPassHash = "14|8|1|...|..."}
hashPass :: MonadIO m => Pass -> m PassHash
hashPass pass = do
  salt <- liftIO newSalt
  pure $ hashPassWithSalt salt pass

-- | Hash a password with the given 'Salt'.
--
-- The resulting 'PassHash' has the parameters used to hash it, as well as the
-- 'Salt' appended to it, separated by @|@.
--
-- The input 'Salt' and resulting 'PassHash' are both byte-64 encoded.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> hashPassWithSalt salt (mkPass "foobar")
-- PassHash {unPassHash = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'.  'hashPass'
-- generates a new 'Salt' everytime it is called.)
--
-- This function uses the hash function from the scrypt package: 'encryptPass'.
hashPassWithSalt :: Salt -> Pass -> PassHash
hashPassWithSalt salt pass =
  scryptEncryptedPassToPassHash $
    encryptPass defaultParams salt (passToScryptPass pass)

-- | The result of a checking a password against a hashed version.  This is
-- returned by 'checkPass'.
data PassCheck
  = PassCheckSuccess
  -- ^ The password check was successful. The plain-text password matches the
  -- hashed password.
  | PassCheckFail
  -- ^ The password check failed.  The plain-text password does not match the
  -- hashed password.
  deriving (Eq, Read, Show)

-- | Check a 'Pass' against a 'PassHash'.
--
-- Returns 'PassCheckSuccess' on success.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = mkPass "foobar"
-- >>> let passHash = hashPassWithSalt salt pass
-- >>> checkPass pass passHash
-- PassCheckSuccess
--
-- Returns 'PassCheckFail' If an incorrect 'Pass' or 'PassHash' is used.
--
-- >>> let badpass = mkPass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPassHash = hashPassWithSalt salt "foobar" in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash -> PassCheck
checkPass pass passHash =
  if verifyPass' (passToScryptPass pass) (passHashToScryptEncryptedPass passHash)
  then PassCheckSuccess
  else PassCheckFail

-- | Generate a random 32-byte salt.
newSalt :: MonadIO m => m Salt
newSalt = liftIO Scrypt.newSalt

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
