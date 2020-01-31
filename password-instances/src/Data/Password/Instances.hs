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

This module provides additional typeclass instances for 'Pass' and 'PassHash'.

See the "Data.Password" module for more information.
-}

module Data.Password.Instances () where

import Data.Aeson (FromJSON(..))
import Data.Password (Pass, PassHash(..), mkPass)
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
-- >>> import Data.Password.Scrypt (defaultParams, hashPassWithSalt)
-- >>> import Database.Persist.Class (PersistField(toPersistValue))
-- >>> import Web.HttpApiData (parseUrlPiece)

-- | This instance allows a 'Pass' to be created from a JSON blob.
--
-- >>> let maybePass = decode "\"foobar\"" :: Maybe Pass
-- >>> fmap unsafeShowPassword maybePass
-- Just "foobar"
--
-- There is no instance for 'ToJSON' for 'Pass' because we don't want to
-- accidentally encode a plain-text 'Pass' to JSON and send it to the end-user.
--
-- Similarly, there is no 'ToJSON' and 'FromJSON' instance for 'PassHash'
-- because we don't want to accidentally send the password hash to the end
-- user.
instance FromJSON Pass where
  parseJSON = fmap mkPass . parseJSON

-- | This instance allows a 'Pass' to be created with functions like
-- 'Web.HttpApiData.parseUrlPiece' or 'Web.HttpApiData.parseQueryParam'.
--
-- >>> let eitherPass = parseUrlPiece "foobar"
-- >>> fmap unsafeShowPassword eitherPass
-- Right "foobar"
instance FromHttpApiData Pass where
  parseUrlPiece = fmap mkPass . parseUrlPiece

-- | This instance allows a 'PassHash' to be stored as a field in a database using
-- "Database.Persist".
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = mkPass "foobar"
-- >>> let hashedPassword = hashPassWithSalt defaultParams salt pass
-- >>> toPersistValue hashedPassword
-- PersistText "16|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|BH0oidcU/4Ec7Co4EM+LQ6xp39//MnOUhqmNeOnOz/nl4JHNXEJBw5dPdi3wTStYr+e1SmJkzHJrMvUJYNxK1w=="
--
-- In the example above, the long 'PersistText' will be the value you store in
-- the database.
--
-- We don't provide an instance of 'PersistField' for 'Pass', because we don't
-- want to make it easy to store a plain-text password in the database.
instance PersistField (PassHash a) where
  toPersistValue (PassHash hpw) = PersistText hpw
  fromPersistValue (PersistText txt) = Right $ PassHash txt
  fromPersistValue (PersistByteString bs) = Right $ PassHash $ TE.decodeUtf8 bs
  fromPersistValue _ = Left "did not parse PassHash from PersistValue"

-- | This instance allows a 'PassHash' to be stored as a field in an SQL
-- database in "Database.Persist.Sql".
deriving newtype instance PersistFieldSql (PassHash a)
