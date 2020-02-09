{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.Scrypt
Copyright   : (c) Dennis Gosnell, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX
-}
-- I think the portability is broadened to
-- whatever, now that we use cryptonite... I think
module Data.Password.Scrypt (
  -- * Hash Passwords (scrypt)
    hashPass
  , Scrypt
  -- * Verify Passwords (scrypt)
  , checkPass
  -- * Hashing Manually (DISADVISED)
  --
  -- If you have any doubt about your knowledge of cryptography and/or the
  -- /scrypt/ algorithm, please, please just use 'hashPass'.
  , hashPassWithParams
  , hashPassWithSalt
  , ScryptParams(..)
  , defaultParams
  , newSalt
  ) where

import Control.Monad (guard)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.KDF.Scrypt as Scrypt
import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as C8 (length)
import Data.Maybe (fromMaybe)
import Data.Password.Internal hiding (newSalt)
import qualified Data.Password.Internal
import Data.Text (Text)
import qualified Data.Text as T (intercalate, pack, split, unpack)
import Data.Text.Encoding (encodeUtf8)
import Text.Read (readMaybe)

-- | Phantom type for keeping 'PassHash'es apart
--
-- @since 2.0.0.0
data Scrypt

-- $setup
-- >>> :set -XFlexibleInstances
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), Blind(Blind), vector)
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- >>> instance Arbitrary (Salt a) where arbitrary = Salt . pack <$> vector 32
-- >>> instance Arbitrary Pass where arbitrary = fmap Pass arbitrary
-- >>> let testParams = defaultParams {scryptRounds = 12}
-- >>> instance Arbitrary (PassHash Scrypt) where arbitrary = hashPassWithSalt testParams <$> arbitrary <*> arbitrary

-- | Hash the 'Pass' using the /scrypt/ hash algorithm
--
-- >>> hashPass $ mkPass "foobar"
-- PassHash {unPassHash = "16|8|1|...|..."}
hashPass :: MonadIO m => Pass -> m (PassHash Scrypt)
hashPass = hashPassWithParams defaultParams

-- | Parameters used in the /scrypt/ hashing algorithm.
--
-- @since 2.0.0.0
data ScryptParams = ScryptParams {
  scryptSalt :: Int,
  -- ^ Bytes to randomly generate as a unique salt, default is __32__
  scryptRounds :: Int,
  -- ^ log2(N) rounds to hash, default is __16__ (i.e. 2^16 rounds)
  scryptBlockSize :: Int,
  -- ^ Block size, defaults to __8__
  scryptParallellism :: Int,
  -- ^ Parallellism factor, defaults to __1__
  scryptOutputLength :: Int
  -- ^ Output key length in bytes, defaults to __64__
} deriving (Eq, Show)

-- | Default "industry standard" parameters for the /scrypt/ algorithm.
--
-- @since 2.0.0.0
defaultParams :: ScryptParams
defaultParams = ScryptParams {
  scryptSalt = 32,
  scryptRounds = 16,
  scryptBlockSize = 8,
  scryptParallellism = 1,
  scryptOutputLength = 64
}

-- | Hash a password with the given 'ScryptParams' and also with the given 'Salt'
-- instead of using 'scryptSalt' from 'ScryptParams'.
--
-- The resulting 'PassHash' has the parameters used to hash it, as well as the
-- 'Salt' appended to it, separated by @|@.
--
-- The input 'Salt' and resulting 'PassHash' are both byte-64 encoded.
--
-- >>> let salt = Salt "abcdefghijklmnopqrstuvwxyz012345"
-- >>> hashPassWithSalt defaultParams salt (mkPass "foobar")
-- PassHash {unPassHash = "16|8|1|YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=|BH0oidcU/4Ec7Co4EM+LQ6xp39//MnOUhqmNeOnOz/nl4JHNXEJBw5dPdi3wTStYr+e1SmJkzHJrMvUJYNxK1w=="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'. 'hashPass'
-- generates a new 'Salt' everytime it is called.)
hashPassWithSalt :: ScryptParams -> Salt Scrypt -> Pass -> PassHash Scrypt
hashPassWithSalt params@ScryptParams{..} s@(Salt salt) pass =
  PassHash $ T.intercalate "|"
    [ t scryptRounds
    , t scryptBlockSize
    , t scryptParallellism
    , b64 salt
    , b64 key
    ]
  where
    t :: forall a. Show a => a -> Text
    t = T.pack . show
    b64 = Base64.encodeBase64
    key = hashPassWithSalt' params s pass

-- | Only for internal use
hashPassWithSalt' :: ScryptParams -> Salt Scrypt -> Pass -> ByteString
hashPassWithSalt' ScryptParams{..} (Salt salt) (Pass pass) =
    Scrypt.generate params bsPass (convert salt :: Bytes)
  where
    bsPass = encodeUtf8 pass
    params = Scrypt.Parameters {
        n = 2 ^ scryptRounds,
        r = scryptBlockSize,
        p = scryptParallellism,
        outputLength = scryptOutputLength
      }


-- | Hash a password using the /scrypt/ algorithm with the given 'ScryptParams'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- /scrypt/ algorithm, please, please just use 'hashPass'.
--
-- @since 2.0.0.0
hashPassWithParams :: MonadIO m => ScryptParams -> Pass -> m (PassHash Scrypt)
hashPassWithParams scryptParams pass = liftIO $ do
    salt <- newSalt
    return $ hashPassWithSalt scryptParams salt pass

-- | Check a 'Pass' against a 'PassHash' 'Scrypt'.
--
-- Returns 'PassCheckSuccess' on success.
--
-- >>> let pass = mkPass "foobar"
-- >>> passHash <- hashPass pass
-- >>> checkPass pass passHash
-- PassCheckSuccess
--
-- Returns 'PassCheckFail' if an incorrect 'Pass' or 'PassHash' 'Scrypt' is used.
--
-- >>> let badpass = mkPass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPassHash = hashPassWithSalt testParams salt "foobar" in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash Scrypt -> PassCheck
checkPass pass (PassHash passHash) =
  fromMaybe PassCheckFail $ do
    let paramList = T.split (== '|') passHash
    guard $ length paramList == 5
    let [ scryptRoundsT,
          scryptBlockSizeT,
          scryptParallellismT,
          salt64,
          hashedKey64 ] = paramList
    scryptRounds <- readT scryptRoundsT
    scryptBlockSize <- readT scryptBlockSizeT
    scryptParallellism <- readT scryptParallellismT
    salt <- from64 salt64
    hashedKey <- from64 hashedKey64
    let scryptOutputLength = C8.length hashedKey -- only here because of warnings
        producedKey = hashPassWithSalt' ScryptParams{..} (Salt salt) pass
    guard $ hashedKey == producedKey
    return PassCheckSuccess
  where
    scryptSalt = 32 -- only here because of warnings
    from64 = either (\_ -> Nothing) pure . Base64.decodeBase64 . encodeUtf8
    readT :: forall a. Read a => Text -> Maybe a
    readT = readMaybe . T.unpack

-- | Generate a random 32-byte salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt Scrypt)
newSalt = Data.Password.Internal.newSalt 32
