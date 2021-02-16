{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.Scrypt
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= scrypt

The @scrypt@ algorithm is a fairly new one. First published
in 2009, but published by the IETF in 2016 as <https://tools.ietf.org/html/rfc7914 RFC 7914>.
Originally used for the Tarsnap backup service, it is
designed to be costly by requiring large amounts of memory.

== Other algorithms

@scrypt@ does increase the memory requirement in contrast to
@'Data.Password.Bcrypt.Bcrypt'@ and @'Data.Password.PBKDF2.PBKDF2'@, but it
turns out it is not as optimal as it could be, and thus others have set out
to search for other algorithms that do fulfill on their promises.
@'Data.Password.Argon2.Argon2'@ seems to be the winner in that search.

That is not to say using @scrypt@ somehow means your passwords
won't be properly protected. The cryptography is sound and
thus is fine for protection against brute-force attacks.
Because of the memory cost, it is generally advised to use
@'Data.Password.Bcrypt.Bcrypt'@ if you're not sure this might be a
problem on your system.
-}

module Data.Password.Scrypt (
  -- * Algorithm
  Scrypt
  -- * Plain-text Password
  , Password
  , mkPassword
  -- * Hash Passwords (scrypt)
  , hashPassword
  , PasswordHash(..)
  -- * Verify Passwords (scrypt)
  , checkPassword
  , PasswordCheck(..)
  -- * Hashing Manually (scrypt)
  , hashPasswordWithParams
  , defaultParams
  , ScryptParams(..)
  -- ** Hashing with salt (DISADVISED)
  --
  -- | Hashing with a set 'Salt' is almost never what you want
  -- to do. Use 'hashPassword' or 'hashPasswordWithParams' to have
  -- automatic generation of randomized salts.
  , hashPasswordWithSalt
  , newSalt
  , Salt(..)
  -- * Unsafe debugging function to show a Password
  , unsafeShowPassword
  , -- * Setup for doctests.
    -- $setup
  ) where

import Control.Monad (guard)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.KDF.Scrypt as Scrypt (Parameters(..), generate)
import Data.ByteArray (Bytes, constEq, convert)
import Data.ByteString (ByteString)
import Data.ByteString.Base64 (encodeBase64)
import qualified Data.ByteString.Char8 as C8 (length)
import Data.Maybe (fromMaybe)
import qualified Data.Text as T (intercalate, split)
import Data.Word (Word32)

import Data.Password.Types (
    Password
  , PasswordHash(..)
  , mkPassword
  , unsafeShowPassword
  , Salt(..)
  )
import Data.Password.Internal (
    PasswordCheck(..)
  , from64
  , readT
  , showT
  , toBytes
  )
import qualified Data.Password.Internal (newSalt)

-- | Phantom type for __scrypt__
--
-- @since 2.0.0.0
data Scrypt

-- $setup
-- >>> :set -XFlexibleInstances
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password.Types
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), Blind(Blind), vector)
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- >>> instance Arbitrary (Salt a) where arbitrary = Salt . pack <$> vector 32
-- >>> instance Arbitrary Password where arbitrary = fmap mkPassword arbitrary
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> let testParams = defaultParams {scryptRounds = 10}

-- -- >>> instance Arbitrary (PasswordHash Scrypt) where arbitrary = hashPasswordWithSalt testParams <$> arbitrary <*> arbitrary

-- | Hash the 'Password' using the 'Scrypt' hash algorithm
--
-- >>> hashPassword $ mkPassword "foobar"
-- PasswordHash {unPasswordHash = "14|8|1|...|..."}
hashPassword :: MonadIO m => Password -> m (PasswordHash Scrypt)
hashPassword = hashPasswordWithParams defaultParams

-- TODO: Add way to parse the following. From [https://hashcat.net/wiki/doku.php?id=example_hashes]
-- SCRYPT:1024:1:1:MDIwMzMwNTQwNDQyNQ==:5FW+zWivLxgCWj7qLiQbeC8zaNQ+qdO0NUinvqyFcfo=

-- | Parameters used in the 'Scrypt' hashing algorithm.
--
-- @since 2.0.0.0
data ScryptParams = ScryptParams {
  scryptSalt :: Word32,
  -- ^ Bytes to randomly generate as a unique salt, default is __32__
  scryptRounds :: Word32,
  -- ^ log2(N) rounds to hash, default is __14__ (i.e. 2^14 rounds)
  scryptBlockSize :: Word32,
  -- ^ Block size, default is __8__
  --
  -- Limits are min: @1@, and max: @scryptBlockSize * scryptParallelism < 2 ^ 30@
  scryptParallelism :: Word32,
  -- ^ Parallelism factor, default is __1__
  --
  -- Limits are min: @0@, and max: @scryptBlockSize * scryptParallelism < 2 ^ 30@
  scryptOutputLength :: Word32
  -- ^ Output key length in bytes, default is __64__
} deriving (Eq, Show)

-- | Default parameters for the 'Scrypt' algorithm.
--
-- >>> defaultParams
-- ScryptParams {scryptSalt = 32, scryptRounds = 14, scryptBlockSize = 8, scryptParallelism = 1, scryptOutputLength = 64}
--
-- @since 2.0.0.0
defaultParams :: ScryptParams
defaultParams = ScryptParams {
  scryptSalt = 32,
  scryptRounds = 14,
  scryptBlockSize = 8,
  scryptParallelism = 1,
  scryptOutputLength = 64
}

-- | Hash a password with the given 'ScryptParams' and also with the given 'Salt'
-- instead of a randomly generated salt using 'scryptSalt' from 'ScryptParams'.
-- Using 'hashPasswordWithSalt' is strongly __disadvised__ and 'hashPasswordWithParams'
-- should be used instead. /Never use a static salt in production applications!/
--
-- The resulting 'PasswordHash' has the parameters used to hash it, as well as the
-- 'Salt' appended to it, separated by @|@.
--
-- The input 'Salt' and resulting 'PasswordHash' are both base64 encoded.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> hashPasswordWithSalt defaultParams salt (mkPassword "foobar")
-- PasswordHash {unPasswordHash = "14|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|nENDaqWBmPKapAqQ3//H0iBImweGjoTqn5SvBS8Mc9FPFbzq6w65maYPZaO+SPamVZRXQjARQ8Y+5rhuDhjIhw=="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPassword'. 'hashPassword'
-- generates a new 'Salt' everytime it is called.)
hashPasswordWithSalt :: ScryptParams -> Salt Scrypt -> Password -> PasswordHash Scrypt
hashPasswordWithSalt params@ScryptParams{..} s@(Salt salt) pass =
  PasswordHash $ T.intercalate "|"
    [ showT scryptRounds
    , showT scryptBlockSize
    , showT scryptParallelism
    , encodeBase64 salt
    , encodeBase64 key
    ]
  where
    key = hashPasswordWithSalt' params s pass

-- | Only for internal use
hashPasswordWithSalt' :: ScryptParams -> Salt Scrypt -> Password -> ByteString
hashPasswordWithSalt' ScryptParams{..} (Salt salt) pass =
    convert (scryptHash :: Bytes)
  where
    scryptHash = Scrypt.generate
        params
        (toBytes $ unsafeShowPassword pass)
        (convert salt :: Bytes)
    params = Scrypt.Parameters {
        n = 2 ^ scryptRounds,
        r = fromIntegral scryptBlockSize,
        p = fromIntegral scryptParallelism,
        outputLength = fromIntegral scryptOutputLength
      }


-- | Hash a password using the 'Scrypt' algorithm with the given 'ScryptParams'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- 'Scrypt' algorithm, please just use 'hashPassword'.
--
-- Advice for setting the parameters:
--
-- * Memory used is about: @(2 ^ 'scryptRounds') * 'scryptBlockSize' * 128@
-- * Increasing 'scryptBlockSize' and 'scryptRounds' will increase CPU time
--   and memory used.
-- * Increasing 'scryptParallelism' will increase CPU time. (since this
--   implementation, like most, runs the 'scryptParallelism' parameter in
--   sequence, not in parallel)
--
-- @since 2.0.0.0
hashPasswordWithParams :: MonadIO m => ScryptParams -> Password -> m (PasswordHash Scrypt)
hashPasswordWithParams params pass = liftIO $ do
    salt <- Data.Password.Internal.newSalt saltLength
    return $ hashPasswordWithSalt params salt pass
  where
    saltLength = fromIntegral $ scryptSalt params

-- | Check a 'Password' against a 'PasswordHash' 'Scrypt'.
--
-- Returns 'PasswordCheckSuccess' on success.
--
-- >>> let pass = mkPassword "foobar"
-- >>> passHash <- hashPassword pass
-- >>> checkPassword pass passHash
-- PasswordCheckSuccess
--
-- Returns 'PasswordCheckFail' if an incorrect 'Password' or 'PasswordHash' 'Scrypt' is used.
--
-- >>> let badpass = mkPassword "incorrect-password"
-- >>> checkPassword badpass passHash
-- PasswordCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPasswordHash = hashPasswordWithSalt testParams salt "foobar" in checkPassword badpass correctPasswordHash == PasswordCheckFail
checkPassword :: Password -> PasswordHash Scrypt -> PasswordCheck
checkPassword pass (PasswordHash passHash) =
  fromMaybe PasswordCheckFail $ do
    let paramList = T.split (== '|') passHash
    guard $ length paramList == 5
    let [ scryptRoundsT,
          scryptBlockSizeT,
          scryptParallelismT,
          salt64,
          hashedKey64 ] = paramList
    scryptRounds <- readT scryptRoundsT
    scryptBlockSize <- readT scryptBlockSizeT
    scryptParallelism <- readT scryptParallelismT
    salt <- from64 salt64
    hashedKey <- from64 hashedKey64
    let scryptOutputLength = fromIntegral $ C8.length hashedKey
        producedKey = hashPasswordWithSalt' ScryptParams{..} (Salt salt) pass
    guard $ hashedKey `constEq` producedKey
    return PasswordCheckSuccess
  where
    scryptSalt = 32 -- only here because of warnings

-- | Generate a random 32-byte @scrypt@ salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt Scrypt)
newSalt = Data.Password.Internal.newSalt 32
