{-# LANGUAGE InstanceSigs #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

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
  , -- * Setup for doctests.
    -- $setup
  ) where

import Data.Password (Pass(..), PassCheck(..), PassHash(..), Salt(..), checkPass, hashPass, hashPassWithSalt, newSalt)


-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), vector)
-- >>> import Test.QuickCheck.Instances.ByteString ()
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- 'Arbitrary' instances for types exported from this library.
--
-- >>> instance Arbitrary Salt where arbitrary = Salt . pack <$> vector 32
-- >>> instance Arbitrary Pass where arbitrary = fmap Pass arbitrary
-- >>> instance Arbitrary PassHash where arbitrary = hashPassWithSalt <$> arbitrary <*> arbitrary
--
-- 'Arbitrary' instances for types exported from "Crypto.Scrypt".
--
-- >>> instance Arbitrary Scrypt.Pass where arbitrary = fmap Scrypt.Pass arbitrary
-- >>> instance Arbitrary EncryptedPass where arbitrary = encryptPass defaultParams <$> arbitrary <*> arbitrary
