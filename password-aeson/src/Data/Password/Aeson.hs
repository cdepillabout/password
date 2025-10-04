{-# LANGUAGE DataKinds #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
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

module Data.Password.Aeson () where

import Data.Aeson (FromJSON(..), ToJSON(..))
import Data.Password.Types (Password, mkPassword)
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
