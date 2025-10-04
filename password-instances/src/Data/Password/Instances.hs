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

import Data.Password.Aeson  as E
import Data.Password.HttpApiData as E
import Data.Password.Persistent as E
