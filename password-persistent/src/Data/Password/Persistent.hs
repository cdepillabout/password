{-# LANGUAGE CPP #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE GeneralizedNewtypeDeriving #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE StandaloneDeriving #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

{-|
Module      : Data.Password.Persistent
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This module provides `persistent` typeclass instances
for 'Password' and 'PasswordHash'.

See the "Data.Password.Types" module for more information.
-}

module Data.Password.Persistent () where

import Data.Password.Types (Password, PasswordHash(..))
#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (pack)
import Data.Text.Encoding as TE (decodeUtf8')
import Database.Persist (PersistValue(..))
import Database.Persist.Class (PersistField(..))
import Database.Persist.Sql (PersistFieldSql(..))
import GHC.TypeLits (TypeError, ErrorMessage(..))

-- $setup
-- >>> :set -XOverloadedStrings
-- >>> :set -XDataKinds
--
-- Import needed functions.
--
-- >>> import Data.Password.Bcrypt (Salt(..), hashPasswordWithSalt, unsafeShowPassword)
-- >>> import Data.Password.Types (mkPassword)
-- >>> import Database.Persist.Class (PersistField(toPersistValue))

type ErrMsg e = 'Text "Warning! Tried to convert plain-text Password to " ':<>: 'Text e ':<>: 'Text "!"
          ':$$: 'Text "  This is likely a security leak. Please make sure whether this was intended."
          ':$$: 'Text "  If this is intended, please use 'unsafeShowPassword' before converting to " ':<>: 'Text e
          ':$$: 'Text ""

-- | This instance allows a 'PasswordHash' to be stored as a field in a database using
-- "Database.Persist".
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> let pass = mkPassword "foobar"
-- >>> let hashedPassword = hashPasswordWithSalt 10 salt pass
-- >>> toPersistValue hashedPassword
-- PersistText "$2b$10$WUHhXETkX0fnYkrqZU3ta.N8Utt4U77kW4RVbchzgvBvBBEEdCD/u"
--
-- In the example above, the long 'PersistText' will be the value you store in
-- the database.
--
-- We don't provide an instance of 'PersistField' for 'Password', because we don't
-- want to make it easy to store a plain-text password in the database.
instance PersistField (PasswordHash a) where
  toPersistValue (PasswordHash hpw) = PersistText hpw
  fromPersistValue = \case
      PersistText txt -> Right $ PasswordHash txt
      PersistByteString bs ->
        either failed (Right . PasswordHash) $ TE.decodeUtf8' bs
      _ -> Left "did not parse PasswordHash from PersistValue"
    where
      failed e = Left $ "Failed decoding PasswordHash to UTF8: " <> pack (show e)

-- | This instance allows a 'PasswordHash' to be stored as a field in an SQL
-- database in "Database.Persist.Sql".
deriving newtype instance PersistFieldSql (PasswordHash a)

-- | Type error! Do not store plain-text 'Password's in your database!
instance TypeError (ErrMsg "PersistValue") => PersistField Password where
  toPersistValue = error "unreachable"
  fromPersistValue = error "unreachable"
