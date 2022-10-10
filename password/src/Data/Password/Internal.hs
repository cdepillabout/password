{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
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
  , newSalt
  -- * Utility
  , toBytes
  , fromBytes
  , from64
  , unsafePad64
  , readT
  , showT
  , -- * Setup for doctests.
    -- $setup
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Random (getRandomBytes)
import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 (decodeBase64)
#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text as T (
    Text,
    length,
    pack,
    replicate,
    unpack,
 )
import Data.Password.Types (Salt(..))
import Data.Text.Encoding (decodeUtf8, encodeUtf8)
import Text.Read (readMaybe)

-- $setup
-- >>> import Data.ByteString as B (length)
-- >>> import Data.ByteString.Base64 (encodeBase64)
-- >>> import Data.Text as T (dropWhileEnd)
-- >>> import Data.Word (Word16)
-- >>> import Test.QuickCheck (ioProperty, quickCheck, (===))
-- >>> import Test.QuickCheck.Instances.ByteString()

-- | Generate a random x-byte-long salt.
--
-- >>> :{
-- quickCheck $ \w ->
--   ioProperty $ do
--     let i :: Num a => a
--         i = fromIntegral (w :: Word16)
--     Salt bs <- newSalt i
--     pure $ B.length bs === i
-- :}
-- +++ OK, passed 100 tests.
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

-- | (UNSAFE) Pad a base64 text to "length `rem` 4 == 0" with "="
--
-- prop> \bs -> let b64 = encodeBase64 bs in unsafePad64 (T.dropWhileEnd (== '=') b64) == b64
unsafePad64 :: Text -> Text
unsafePad64 t
    | remains == 0 = t
    | otherwise = t <> pad
  where
    remains = T.length t `rem` 4
    pad = T.replicate (4 - remains) "="
