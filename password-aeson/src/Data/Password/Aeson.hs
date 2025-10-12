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
Module      : Data.Password.Aeson
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides additional typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password.Types" module for more information.
-}

module Data.Password.Aeson
  ( FromJSON (..),
    ToJSON (..),
    ExposedPassword (..),
  ) where

import Data.Aeson (FromJSON(..), ToJSON(..))
import Data.Password.Types
import GHC.TypeLits (TypeError, ErrorMessage(..))

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
--
-- Import needed functions.
--
-- >>> import Data.Aeson (decode)
-- >>> import Data.Password.Bcrypt (Salt(..), hashPasswordWithSalt, unsafeShowPassword)

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

type ErrMsg = 'Text "Warning! Tried to convert plain-text Password to JSON!"
        ':$$: 'Text "  This is likely a security leak. Please make sure whether this was intended."
        ':$$: 'Text "  If this is intended, please use 'unsafeShowPassword' before converting to JSON"
        ':$$: 'Text ""

-- | Type error! Do not use 'toJSON' on a 'Password'!
instance TypeError ErrMsg => ToJSON Password where
  toJSON = error "unreachable"

-- | WARNING: DO NOT USE UNLESS ABSOLUTELY NECESSARY!
--
-- Using this newtype will allow your plain text password to be turned into
-- JSON. Keep this type tightly bound to only the section where you want to
-- expose the `Password`, since it's easy for a bigger type that contains
-- this `ExposedPassword` to be logged or printed as JSON, and now you've
-- accidentally leaked passwords in your logs or database.
newtype ExposedPassword = ExposedPassword Password
  deriving newtype (FromJSON)

instance ToJSON ExposedPassword where
  toJSON (ExposedPassword p) = toJSON $ unsafeShowPassword p

deriving newtype instance FromJSON (PasswordHash a)

deriving newtype instance ToJSON (PasswordHash a)
