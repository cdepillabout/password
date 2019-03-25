{-# LANGUAGE OverloadedStrings #-}

module Data.Password
  ( Pass(..)
  , PassHash(..)
  , Salt(..)
  , hashPass
  , hashPassWithSalt

  ) where

import Crypto.Scrypt (Salt(..), encryptPassIO)
import qualified Crypto.Scrypt as Scrypt
import Data.Text (Text)

data Pass = Pass
  { unPass :: Text
  } deriving (Eq, IsString, Ord, Read, Show)

data PassHash = PassHash
  { unPassHash :: Text
  } deriving (Eq, Ord, Read, Show)

-- | Convert an 'Scrypt.Pass' to our 'Pass' type.
--
-- >>> passToScryptPass $ Pass "foobar"
-- hello
passToScryptPass :: Pass -> Scrypt.Pass
passToScryptPass (Pass pass) = Scrypt.Pass $ encodeUtf8 pass

scryptEncryptedPassToPassHash :: EncryptedPass -> PassHash
scryptEncryptedPassToPassHash (EncryptedPass encryptPass) =
  PassHash $ decodeUtf8 encryptPass

hashPass :: MonadIO m => Pass -> m PassHash
hashPass pass = do
  salt <- liftIO newSalt
  pure $ hashPassWithSalt pass salt

hashPassWithSalt :: Pass -> Salt -> PassHash
hashPassWithSalt (Pass pass) salt =
  scryptEncryptedPassToPassHash $
    encryptPass defaultParams (passToScryptPass pass) salt
