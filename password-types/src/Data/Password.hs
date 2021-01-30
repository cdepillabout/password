{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Data.Password
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This library provides datatypes for interacting with passwords.
It provides the types 'Password' and 'PasswordHash', which correspond
to plain-text and hashed passwords.

== Special instances

There is an accompanying <http://hackage.haskell.org/package/password-instances password-instances>
package that provides canonical typeclass instances for
'Password' and 'PasswordHash' for many common typeclasses, like
<http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON FromJSON> from
<http://hackage.haskell.org/package/aeson aeson>,
<http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistField PersistField>
from
<http://hackage.haskell.org/package/persistent persistent>, etc.

See the <http://hackage.haskell.org/package/password-instances password-instances> package for more information.

-}

module Data.Password (
    -- * Plain-text Password
    Password
  , mkPassword
    -- * Password Hashing
  , PasswordHash(..)
    -- * Unsafe debugging function to show a Password
  , unsafeShowPassword
    -- * Hashing salts
  , Salt (..)
  ) where

import Data.ByteArray (constEq)
import Data.ByteString (ByteString)
import Data.Function (on)
import Data.String (IsString(..))
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)

-- $setup
-- >>> :set -XOverloadedStrings

-- | A plain-text password.
--
-- This represents a plain-text password that has /NOT/ been hashed.
--
-- You should be careful with 'Password'. Make sure not to write it to logs or
-- store it in a database.
--
-- You can construct a 'Password' by using the 'mkPassword' function or as literal
-- strings together with the OverloadedStrings pragma (or manually, by using
-- 'fromString' on a 'String'). Alternatively, you could also use some of the
-- instances in the <http://hackage.haskell.org/package/password-instances password-instances>
-- library.
newtype Password = Password Text
  deriving (IsString)

-- | CAREFUL: 'Show'-ing a 'Password' will always print @"**PASSWORD**"@
--
-- >>> show ("hello" :: Password)
-- "**PASSWORD**"
instance Show Password where
 show _ = "**PASSWORD**"

-- | Construct a 'Password'
mkPassword :: Text -> Password
mkPassword = Password
{-# INLINE mkPassword #-}

-- | This is an unsafe function that shows a password in plain-text.
--
-- >>> unsafeShowPassword ("foobar" :: Password)
-- "foobar"
--
-- You should generally not use this function.
unsafeShowPassword :: Password -> Text
unsafeShowPassword (Password pass) = pass
{-# INLINE unsafeShowPassword #-}

-- | A hashed password.
--
-- This represents a password that has been put through a hashing function.
-- The hashed password can be stored in a database.
newtype PasswordHash a = PasswordHash
  { unPasswordHash :: Text
  } deriving (Ord, Read, Show)

instance Eq (PasswordHash a)  where
  (==) = constEq `on` encodeUtf8 . unPasswordHash

-- | A salt used by a hashing algorithm.
newtype Salt a = Salt
  { getSalt :: ByteString
  } deriving (Eq, Show)
