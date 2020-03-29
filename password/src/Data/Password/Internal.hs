{-# LANGUAGE DataKinds #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures #-}

{-|
Module      : Data.Password.Internal
Copyright   : (c) Dennis Gosnell, 2019
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX
-}

module Data.Password.Internal (
    -- * Global types
    Pass(..)
  , mkPass
  , PassHash(..)
  , PassCheck(..)
  , Salt(..)
  , newSalt
  -- * Unsafe functions
  , unsafeShowPassword
  , unsafeShowPasswordText
  -- * Utility
  , toBytes
  , fromBytes
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Random (getRandomBytes)
import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)
import Data.String (IsString(..))
import Data.Text (Text, unpack)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)

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
-- >>> show ("hello" :: Pass)
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
{-# INLINE mkPass #-}

-- | A salt used by a hashing algorithm.
--
-- @since 2.0.0.0
newtype Salt a = Salt ByteString
  deriving (Eq, Show)

-- | Generate a random x-byte salt.
--
-- @since 2.0.0.0
newSalt :: MonadIO m => Int -> m (Salt a)
newSalt i = liftIO $ Salt <$> getRandomBytes i
{-# INLINE newSalt #-}

-- | This is an unsafe function that shows a password in plain-text.
--
-- >>> unsafeShowPasswordText ("foobar" :: Pass)
-- "foobar"
--
-- You should generally not use this function.
unsafeShowPassword :: Pass -> String
unsafeShowPassword = unpack . unsafeShowPasswordText
{-# INLINE unsafeShowPassword #-}

-- | This is like 'unsafeShowPassword' but produces a 'Text' instead of a
-- 'String'.
unsafeShowPasswordText :: Pass -> Text
unsafeShowPasswordText (Pass pass) = pass
{-# INLINE unsafeShowPasswordText #-}

-- | A hashed password.
--
-- This represents a password that has been put through a hashing function.
-- The hashed password can be stored in a database.
newtype PassHash a = PassHash
  { unPassHash :: Text
  } deriving (Eq, Ord, Read, Show)

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

-- | Converting 'Text' to 'Bytes'
toBytes :: Text -> Bytes
toBytes = convert . encodeUtf8
{-# INLINE toBytes #-}

-- | Converting 'Bytes' to 'Text'
fromBytes :: Bytes -> Text
fromBytes = decodeUtf8 . convert
{-# INLINE fromBytes #-}
