{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-|
Module      : Data.Password.Internal
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX
-}

module Data.Password.Internal (
    -- * Global types
    Password(..)
  , mkPassword
  , PasswordHash(..)
  , PasswordCheck(..)
  , Salt(..)
  , newSalt
  -- * Unsafe function
  , unsafeShowPassword
  -- * Utility
  , toBytes
  , fromBytes
  , from64
  , readT
  , showT
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Random (getRandomBytes)
import Data.ByteArray (Bytes, constEq, convert)
import Data.ByteString (ByteString)
import Data.Function (on)
import Data.ByteString.Base64 (decodeBase64)
import Data.String (IsString(..))
import Data.Text as T (Text, pack, unpack)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Text.Read (readMaybe)


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
--
-- @since 1.0.0.0
instance Show Password where
 show _ = "**PASSWORD**"

-- | Construct a 'Password'
--
-- @since 1.0.0.0
mkPassword :: Text -> Password
mkPassword = Password
{-# INLINE mkPassword #-}

-- | A salt used by a hashing algorithm.
--
-- @since 2.0.0.0
newtype Salt a = Salt ByteString
  deriving (Eq, Show)

-- | Generate a random x-byte-long salt.
--
-- @since 2.0.0.0
newSalt :: MonadIO m => Int -> m (Salt a)
newSalt i = liftIO $ Salt <$> getRandomBytes i
{-# INLINE newSalt #-}

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

-- | The result of checking a password against a hashed version. This is
-- returned by the @checkPassword@ functions.
data PasswordCheck
  = PasswordCheckSuccess
  -- ^ The password check was successful. The plain-text password matches the
  -- hashed password.
  | PasswordCheckFail
  -- ^ The password check failed. The plain-text password does not match the
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

-- | Decodes a base64 'Text' to a regular 'ByteString' (if possible)
from64 :: Text -> Maybe ByteString
from64 = toMaybe . decodeBase64 . encodeUtf8
  where
    toMaybe = either (const Nothing) Just
{-# INLINE from64 #-}

-- | Same as 'read' but works on 'Text'
readT :: forall a. Read a => Text -> Maybe a
readT = readMaybe . T.unpack
{-# INLINE readT #-}

-- | Same as 'show' but works on 'Text'
showT :: forall a. Show a => a -> Text
showT = T.pack . show
{-# INLINE showT #-}
