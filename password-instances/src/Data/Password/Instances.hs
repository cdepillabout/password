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

This module provides the same interface as "Data.Password", but it also
provides additional typeclass instances for 'Pass' and 'PassHash'.

See the "Data.Password" module for more information.
-}

module Data.Password.Instances
  (
    -- * Plaintext Password
    Pass(..)
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

import Data.Aeson (FromJSON)
import Data.Password
import Database.Persist.Class (PersistField)
import Database.Persist.Sql (PersistFieldSql)
import Web.HttpApiData (FromHttpApiData)


-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed functions.
--
-- >>> import Data.Aeson (decode)
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
deriving newtype instance FromJSON Pass

-- | This instance allows a 'Pass' to be created with functions like
-- 'Web.HttpApiData.parseUrlPiece' or 'Web.HttpApiData.parseQueryParam'.
--
-- >>> let eitherPass = parseUrlPiece "foobar"
-- >>> fmap unsafeShowPassword eitherPass
-- Right "foobar"
deriving newtype instance FromHttpApiData Pass

-- | This instance allows a 'PassHash' to be stored as a field in a database using
-- "Database.Persist".
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let pass = Pass "foobar"
-- >>> let hashedPassword = hashPassWithSalt (Pass "foobar") salt
-- >>> toPersistValue hashedPassword
-- PersistText "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="
--
-- In the example above, the long 'PersistText' will be the value you store in
-- the database.
--
-- We don't provide an instance of 'PersistField' for 'Pass', because we don't
-- want to make it easy to store a plain-text password in the database.
deriving newtype instance PersistField PassHash

-- | This instance allows a 'PassHash' to be stored as a field in an SQL
-- database in "Database.Persist.Sql".
deriving newtype instance PersistFieldSql PassHash
