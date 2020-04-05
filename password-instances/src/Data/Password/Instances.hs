{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|
Module      : Data.Password.Instances
Copyright   : (c) Dennis Gosnell, 2019
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides additional typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password" module for more information.
-}

module Data.Password.Instances () where

import Data.Aeson (FromJSON(..))
import Data.Password (Password, PasswordHash(..), mkPassword)
import Data.Text.Encoding as TE (decodeUtf8)
import Database.Persist (PersistValue(..))
import Database.Persist.Class (PersistField(..))
import Database.Persist.Sql (PersistFieldSql(..))
import Web.HttpApiData (FromHttpApiData(..))


-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
--
-- Import needed functions.
--
-- >>> import Data.Aeson (decode)
-- >>> import Data.Password (Salt(..), unsafeShowPassword)
-- >>> import Data.Password.Scrypt (defaultParams, hashPasswordWithSalt)
-- >>> import Database.Persist.Class (PersistField(toPersistValue))
-- >>> import Web.HttpApiData (parseUrlPiece)

-- | This instance allows a 'Password' to be created from a JSON blob.
--
-- >>> let maybePassword = decode "\"foobar\"" :: Maybe Password
-- >>> fmap unsafeShowPassword maybePassword
-- Just "foobar"
--
-- There is no instance for 'ToJSON' for 'Password' because we don't want to
-- accidentally encode a plain-text 'Password' to JSON and send it to the end-user.
--
-- Similarly, there is no 'ToJSON' and 'FromJSON' instance for 'PasswordHash'
-- because we don't want to accidentally send the password hash to the end
-- user.
instance FromJSON Password where
  parseJSON = fmap mkPassword . parseJSON

-- | This instance allows a 'Password' to be created with functions like
-- 'Web.HttpApiData.parseUrlPiece' or 'Web.HttpApiData.parseQueryParam'.
--
-- >>> let eitherPassword = parseUrlPiece "foobar"
-- >>> fmap unsafeShowPassword eitherPassword
-- Right "foobar"
instance FromHttpApiData Password where
  parseUrlPiece = fmap mkPassword . parseUrlPiece

-- | This instance allows a 'PasswordHash' to be stored as a field in a database using
-- "Database.Persist".
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = mkPassword "foobar"
-- >>> let hashedPassword = hashPasswordWithSalt defaultParams salt pass
-- >>> toPersistValue hashedPassword
-- PersistText "16|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|BH0oidcU/4Ec7Co4EM+LQ6xp39//MnOUhqmNeOnOz/nl4JHNXEJBw5dPdi3wTStYr+e1SmJkzHJrMvUJYNxK1w=="
--
-- In the example above, the long 'PersistText' will be the value you store in
-- the database.
--
-- We don't provide an instance of 'PersistField' for 'Password', because we don't
-- want to make it easy to store a plain-text password in the database.
instance PersistField (PasswordHash a) where
  toPersistValue (PasswordHash hpw) = PersistText hpw
  fromPersistValue (PersistText txt) = Right $ PasswordHash txt
  fromPersistValue (PersistByteString bs) = Right $ PasswordHash $ TE.decodeUtf8 bs
  fromPersistValue _ = Left "did not parse PasswordHash from PersistValue"

-- | This instance allows a 'PasswordHash' to be stored as a field in an SQL
-- database in "Database.Persist.Sql".
deriving newtype instance PersistFieldSql (PasswordHash a)
