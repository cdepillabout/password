{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.PBKDF2
Copyright   : (c) Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= PBKDF2

== Other algorithms

-}

-- I think the portability is broadened to
-- whatever, now that we use cryptonite... I think
module Data.Password.PBKDF2 (
  -- Algorithm
  PBKDF2
  -- * Plain-text Password
  , Pass
  , mkPass
  -- * Hash Passwords (PBKDF2)
  , hashPass
  , PassHash(..)
  -- * Verify Passwords (PBKDF2)
  , checkPass
  , PassCheck(..)
  -- * Hashing Manually (PBKDF2)
  --
  -- | If you have any doubt about what the parameters do or mean,
  -- please just use 'hashPass'.
  , hashPassWithParams
  , PBKDF2Params(..)
  , PBKDF2Algorithm(..)
  , defaultParams
  -- ** Hashing with salt (DISADVISED)
  --
  -- | Hashing with a set 'Salt' is almost never what you want
  -- to do. Use 'hashPass' or 'hashPassWithParams' to have
  -- automatic generation of randomized salts.
  , hashPassWithSalt
  , Salt(..)
  , newSalt
  -- * Unsafe Debugging Functions for Showing a Password
  , unsafeShowPassword
  , unsafeShowPasswordText
  , -- * Setup for doctests.
    -- $setup
  ) where

import Control.Monad (guard)
import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.Hash.Algorithms as Crypto (MD5(..))
import Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteArray (ByteArray, ByteArrayAccess, Bytes, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as C8 (length)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T (intercalate, pack, split)
import Data.Word (Word32)

import Data.Password (
         PassCheck(..)
       , PassHash(..)
       , Salt(..)
       , mkPass
       , unsafeShowPassword
       , unsafeShowPasswordText
       )
import Data.Password.Internal (Pass(..), from64, readT, toBytes)
import qualified Data.Password.Internal (newSalt)


-- | Phantom type for __PBKDF2__
--
-- @since 2.0.0.0
data PBKDF2

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
-- >>> instance Arbitrary (Salt a) where arbitrary = Salt . pack <$> vector 16
-- >>> instance Arbitrary Pass where arbitrary = fmap Pass arbitrary
-- >>> instance Arbitrary (PassHash PBKDF2) where arbitrary = hashPassWithSalt defaultParams <$> arbitrary <*> arbitrary

-- | Hash the 'Pass' using the /PBKDF2/ hash algorithm
--
-- >>> hashPass $ mkPass "foobar"
-- PassHash {unPassHash = "sha512:25000:...:..."}
hashPass :: MonadIO m => Pass -> m (PassHash PBKDF2)
hashPass = hashPassWithParams defaultParams

-- TODO: Add way to parse the following:
-- $pbkdf2-md5$29000$...$...
-- $pbkdf2$25000$...$... (SHA1)
-- $pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A
-- $pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw
-- pbkdf2:sha256:150000:etc.etc.

-- | Parameters used in the /PBKDF2/ hashing algorithm.
--
-- @since 2.0.0.0
data PBKDF2Params = PBKDF2Params {
  pbkdf2Salt :: Word32,
  -- ^ Bytes to randomly generate as a unique salt, default is __16__
  pbkdf2Algorithm :: PBKDF2Algorithm,
  -- ^ Which algorithm to use for hashing, default is __'PBKDF2_SHA512'__
  pbkdf2Iterations :: Word32,
  -- ^ Rounds to hash, default is __25,000__
  pbkdf2OutputLength :: Word32
  -- ^ Output key length in bytes, default is __64__
  --
  -- Limits are min: 1, max: /the amount of entropy of the hashing algorithm/.
  -- This is limited automatically to __16, 20, 32, 64__
  -- for __MD5, SHA1, SHA256, SHA512__, respectively.
} deriving (Eq, Show)

-- | Default parameters for the /PBKDF2/ algorithm.
--
-- @since 2.0.0.0
defaultParams :: PBKDF2Params
defaultParams = PBKDF2Params {
  pbkdf2Salt = 16,
  pbkdf2Algorithm = PBKDF2_SHA512,
  pbkdf2Iterations = 25 * 1000,
  pbkdf2OutputLength = 64
}

-- | Hash a password with the given 'PBKDF2Params' and also with the given 'Salt'
-- instead of a random generated salt using 'pbkdf2Salt' from 'PBKDF2Params'. (cf. 'hashPassWithParams')
-- Using 'hashPassWithSalt' is strongly __disadvised__ and 'hashPassWithParams' should be used instead.
-- /Never use a static salt in production applications!/
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPassWithSalt defaultParams salt (mkPass "foobar")
-- PassHash {unPassHash = "sha512:25000:"}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'. 'hashPass'
-- generates a new 'Salt' everytime it is called.)
hashPassWithSalt :: PBKDF2Params -> Salt PBKDF2 -> Pass -> PassHash PBKDF2
hashPassWithSalt params@PBKDF2Params{..} s@(Salt salt) pass =
  PassHash $ T.intercalate ":"
    [ algToText pbkdf2Algorithm
    , T.pack $ show pbkdf2Iterations
    , b64 salt
    , b64 key
    ]
  where
    b64 = Base64.encodeBase64
    key = hashPassWithSalt' params s pass

-- | Only for internal use
hashPassWithSalt' :: PBKDF2Params -> Salt PBKDF2 -> Pass -> ByteString
hashPassWithSalt' PBKDF2Params{..} (Salt salt) (Pass pass) =
    convert (pbkdf2Hash :: Bytes)
  where
    pbkdf2Hash = algToFunc pbkdf2Algorithm params (toBytes pass) (convert salt :: Bytes)
    params = PBKDF2.Parameters {
        PBKDF2.iterCounts = fromIntegral pbkdf2Iterations,
        PBKDF2.outputLength = fromIntegral $ maxOutputLength pbkdf2Algorithm pbkdf2OutputLength
      }

-- | Hash a password using the /PBKDF2/ algorithm with the given 'PBKDF2Params'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- /PBKDF2/ algorithm, please just use 'hashPass'.
--
-- @since 2.0.0.0
hashPassWithParams :: MonadIO m => PBKDF2Params -> Pass -> m (PassHash PBKDF2)
hashPassWithParams params pass = liftIO $ do
    salt <- Data.Password.Internal.newSalt . fromIntegral $ pbkdf2Salt params
    return $ hashPassWithSalt params salt pass

-- | Check a 'Pass' against a 'PassHash' 'PBKDF2'.
--
-- Returns 'PassCheckSuccess' on success.
--
-- >>> let pass = mkPass "foobar"
-- >>> passHash <- hashPass pass
-- >>> checkPass pass passHash
-- PassCheckSuccess
--
-- Returns 'PassCheckFail' if an incorrect 'Pass' or 'PassHash' 'PBKDF2' is used.
--
-- >>> let badpass = mkPass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPassHash = hashPassWithSalt testParams salt "foobar" in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash PBKDF2 -> PassCheck
checkPass pass (PassHash passHash) =
  fromMaybe PassCheckFail $ do
    let paramList = T.split (== ':') passHash
    guard $ length paramList == 4
    let [ algT,
          iterationsT,
          salt64,
          hashedKey64 ] = paramList
    pbkdf2Algorithm <- textToAlg algT
    pbkdf2Iterations <- readT iterationsT
    salt <- from64 salt64
    hashedKey <- from64 hashedKey64
    let pbkdf2OutputLength = fromIntegral $ C8.length hashedKey
        producedKey = hashPassWithSalt' PBKDF2Params{..} (Salt salt) pass
    guard $ hashedKey == producedKey
    return PassCheckSuccess
  where
    pbkdf2Salt = 16


-- | Type of algorithm to use for hashing PBKDF2 passwords.
data PBKDF2Algorithm =
    PBKDF2_MD5
  | PBKDF2_SHA1
  | PBKDF2_SHA256
  | PBKDF2_SHA512
  deriving (Eq, Show)

-- | Depending on the given algorithm limits the output length.
maxOutputLength :: PBKDF2Algorithm -> Word32 -> Word32
maxOutputLength = min . \case
  PBKDF2_MD5 -> 16
  PBKDF2_SHA1 -> 20
  PBKDF2_SHA256 -> 32
  PBKDF2_SHA512 -> 64

algToText :: PBKDF2Algorithm -> Text
algToText = \case
  PBKDF2_MD5 -> "md5"
  PBKDF2_SHA1 -> "sha1"
  PBKDF2_SHA256 -> "sha256"
  PBKDF2_SHA512 -> "sha512"

textToAlg :: Text -> Maybe PBKDF2Algorithm
textToAlg = \case
  "md5" -> Just $ PBKDF2_MD5
  "sha1" -> Just $ PBKDF2_SHA1
  "sha256" -> Just $ PBKDF2_SHA256
  "sha512" -> Just $ PBKDF2_SHA512
  _ -> Nothing

-- Which function to use, based on the given algorithm
algToFunc :: (ByteArrayAccess password, ByteArrayAccess salt, ByteArray hash)
          => PBKDF2Algorithm -> PBKDF2.Parameters -> password -> salt -> hash
algToFunc = \case
  PBKDF2_MD5 -> PBKDF2.generate (PBKDF2.prfHMAC Crypto.MD5)
  PBKDF2_SHA1 -> PBKDF2.fastPBKDF2_SHA1
  PBKDF2_SHA256 -> PBKDF2.fastPBKDF2_SHA256
  PBKDF2_SHA512 -> PBKDF2.fastPBKDF2_SHA512

-- | Generate a random 16-byte @PBKDF2@ salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt PBKDF2)
newSalt = Data.Password.Internal.newSalt 16
