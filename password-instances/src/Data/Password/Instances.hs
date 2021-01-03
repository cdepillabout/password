{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|
Module      : Data.Password.Instances
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides additional typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password" module for more information.
-}

module Data.Password.Instances () where

import Data.Aeson (FromJSON(..), ToJSON(..))
import Data.Password (Password, PasswordHash(..), mkPassword)
import Data.Text.Encoding as TE (decodeUtf8)
import Database.Persist (PersistValue(..))
import Database.Persist.Class (PersistField(..))
import Database.Persist.Sql (PersistFieldSql(..))
import GHC.TypeLits (TypeError, ErrorMessage(..))
import Web.HttpApiData (FromHttpApiData(..), ToHttpApiData(..))


-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
--
-- Import needed functions.
--
-- >>> import Data.Aeson (decode)
-- >>> import Data.Password (unsafeShowPassword)
-- >>> import Data.Password.Scrypt (Salt(..), defaultParams, hashPasswordWithSalt)
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

type ErrMsg e = 'Text "Warning! Tried to convert plain-text Password to " ':<>: 'Text e ':<>: 'Text "!"
          ':$$: 'Text "  This is likely a security leak. Please make sure whether this was intended."
          ':$$: 'Text "  If this is intended, please use 'unsafeShowPassword' before converting to " ':<>: 'Text e
          ':$$: 'Text ""

-- | Type error! Do not use 'toJSON' on a 'Password'!
instance TypeError (ErrMsg "JSON") => ToJSON Password where
  toJSON = error "unreachable"

-- | This instance allows a 'Password' to be created with functions like
-- 'Web.HttpApiData.parseUrlPiece' or 'Web.HttpApiData.parseQueryParam'.
--
-- >>> let eitherPassword = parseUrlPiece "foobar"
-- >>> fmap unsafeShowPassword eitherPassword
-- Right "foobar"
instance FromHttpApiData Password where
  parseUrlPiece = fmap mkPassword . parseUrlPiece

-- | Type error! Do not transmit plain-text 'Password's over HTTP!
instance TypeError (ErrMsg "HttpApiData") => ToHttpApiData Password where
  toUrlPiece = error "unreachable"

-- | This instance allows a 'PasswordHash' to be stored as a field in a database using
-- "Database.Persist".
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = mkPassword "foobar"
-- >>> let hashedPassword = hashPasswordWithSalt defaultParams salt pass
-- >>> toPersistValue hashedPassword
-- PersistText "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="
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

-- | Type error! Do not store plain-text 'Password's in your database!
instance TypeError (ErrMsg "PersistValue") => PersistField Password where
  toPersistValue = error "unreachable"
  fromPersistValue = error "unreachable"
