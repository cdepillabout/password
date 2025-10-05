{-# OPTIONS_GHC -Wno-dodgy-exports -Wno-unused-imports #-}

{-|
Module      : Data.Password.Instances
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides additional typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password.Types" module for more information.
-}

module Data.Password.Instances (module E) where

#if !defined(FLAG_AESON) && !defined(FLAG_HTTP_API_DATA) && !defined(FLAG_PERSISTENT)
#error "At least one of the flags (aeson, http-api-data, persistent) must be enabled"
#endif

#ifdef FLAG_AESON
import Data.Password.Aeson  as E
#endif

#ifdef FLAG_HTTP_API_DATA
import Data.Password.HttpApiData as E
#endif

#ifdef FLAG_PERSISTENT
import Data.Password.Persistent as E
#endif
