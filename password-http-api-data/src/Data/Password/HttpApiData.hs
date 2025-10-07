{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|
Module      : Data.Password.HttpApiData
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides `http-api-data` typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password.Types" module for more information.
-}

module Data.Password.HttpApiData () where

import Data.Password.Types (Password, PasswordHash(..), mkPassword)
import GHC.TypeLits (TypeError, ErrorMessage(..))
import Web.HttpApiData (FromHttpApiData(..), ToHttpApiData(..))

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
--
-- Import needed functions.
--
-- >>> import Data.Password.Bcrypt (Salt(..), hashPasswordWithSalt, unsafeShowPassword)
-- >>> import Web.HttpApiData (parseUrlPiece)

type ErrMsg e = 'Text "Warning! Tried to convert plain-text Password to " ':<>: 'Text e ':<>: 'Text "!"
          ':$$: 'Text "  This is likely a security leak. Please make sure whether this was intended."
          ':$$: 'Text "  If this is intended, please use 'unsafeShowPassword' before converting to " ':<>: 'Text e
          ':$$: 'Text ""

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
