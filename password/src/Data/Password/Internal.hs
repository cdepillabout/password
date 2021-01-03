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
    PasswordCheck(..)
  , Salt(..)
  , newSalt
  -- * Utility
  , toBytes
  , fromBytes
  , from64
  , readT
  , showT
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Random (getRandomBytes)
import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 (decodeBase64)
import Data.Text as T (Text, pack, unpack)
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Text.Read (readMaybe)


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
readT :: Read a => Text -> Maybe a
readT = readMaybe . T.unpack
{-# INLINE readT #-}

-- | Same as 'show' but works on 'Text'
showT :: Show a => a -> Text
showT = T.pack . show
{-# INLINE showT #-}
