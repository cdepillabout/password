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

The PBKDF2 algorithm is one of the oldest and most solid password
algorithms out there. It has also, however, been shown to be
the least secure out of all major password algorithms. The main
reason for this is that it doesn't make use of any memory cost
or other method of making it difficult for specialized hardware
attacks, like GPU cracking attacks.

It is still, however, used all over the world, since it has been
shown to be a very reliable way to encrypt passwords. And it is
most definitely better than trying to develop a password algorithm
on your own, or god-forbid, not using /any/ encryption on your stored
passwords.

== Other algorithms

Seeing as PBKDF2 is shown to be very weak in terms of protection
against GPU cracking attacks, it is generally advised to go with
@'Data.Password.Bcrypt.Bcrypt'@, if not @'Data.Password.Scrypt.Scrypt'@
or @'Data.Password.Argon2.Argon2'@.
When unsure, @'Data.Password.Bcrypt.Bcrypt'@
would probably be the safest option, as it has no memory cost which
could become a problem if not properly calibrated to the machine
doing the password verifications.
-}

module Data.Password.PBKDF2 (
  -- Algorithm
  PBKDF2
  -- * Plain-text Password
  , Password
  , mkPassword
  -- * Hash Passwords (PBKDF2)
  , hashPassword
  , PasswordHash(..)
  -- * Verify Passwords (PBKDF2)
  , checkPassword
  , PasswordCheck(..)
  -- * Hashing Manually (PBKDF2)
  , hashPasswordWithParams
  , defaultParams
  , PBKDF2Params(..)
  , PBKDF2Algorithm(..)
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
import Crypto.Hash.Algorithms as Crypto (MD5(..))
import Crypto.KDF.PBKDF2 as PBKDF2
import Data.ByteArray (ByteArray, ByteArrayAccess, Bytes, constEq, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as C8 (length)
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T (intercalate, pack, split, stripPrefix)
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
  , toBytes
  )
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
-- >>> import Data.Password.Types
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), Blind(Blind), vector)
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- >>> instance Arbitrary (Salt a) where arbitrary = Salt . pack <$> vector 16
-- >>> instance Arbitrary Password where arbitrary = fmap mkPassword arbitrary
-- >>> let testParams = defaultParams{ pbkdf2Iterations = 5000 }
-- >>> let salt = Salt "abcdefghijklmnop"

-- -- >>> instance Arbitrary (PasswordHash PBKDF2) where arbitrary = hashPasswordWithSalt defaultParams <$> arbitrary <*> arbitrary

-- | Hash the 'Password' using the 'PBKDF2' hash algorithm
--
-- >>> hashPassword $ mkPassword "foobar"
-- PasswordHash {unPasswordHash = "sha512:25000:...:..."}
hashPassword :: MonadIO m => Password -> m (PasswordHash PBKDF2)
hashPassword = hashPasswordWithParams defaultParams

-- TODO: Add way to parse the following:
-- $pbkdf2-md5$29000$...$...
-- $pbkdf2$25000$...$... (SHA1)
-- $pbkdf2-sha256$29000$x9h7j/Ge8x6DMEao1VqrdQ$kra3R1wEnY8mPdDWOpTqOTINaAmZvRMcYd8u5OBQP9A
-- $pbkdf2-sha512$25000$LyWE0HrP2RsjZCxlDGFMKQ$1vC5Ohk2mCS9b6akqsEfgeb4l74SF8XjH.SljXf3dMLHdlY1GK9ojcCKts6/asR4aPqBmk74nCDddU3tvSCJvw

-- | Parameters used in the 'PBKDF2' hashing algorithm.
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

-- | Default parameters for the 'PBKDF2' algorithm.
--
-- >>> defaultParams
-- PBKDF2Params {pbkdf2Salt = 16, pbkdf2Algorithm = PBKDF2_SHA512, pbkdf2Iterations = 25000, pbkdf2OutputLength = 64}
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
-- instead of a randomly generated salt using 'pbkdf2Salt' from 'PBKDF2Params'. (cf. 'hashPasswordWithParams')
-- Using 'hashPasswordWithSalt' is strongly __disadvised__ and 'hashPasswordWithParams' should be used instead.
-- /Never use a static salt in production applications!/
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPasswordWithSalt defaultParams salt (mkPassword "foobar")
-- PasswordHash {unPasswordHash = "sha512:25000:YWJjZGVmZ2hpamtsbW5vcA==:JRElYYrOMe9OIV4LDxaLTgO9ho8fFBVofXoQcdngi7AcuH6Amvmlj2B0y6y1UtQciXXBepSCS+rpy8/vDDQvoA=="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPassword'. 'hashPassword'
-- (and 'hashPasswordWithParams') generates a new 'Salt' everytime it is called.)
hashPasswordWithSalt :: PBKDF2Params -> Salt PBKDF2 -> Password -> PasswordHash PBKDF2
hashPasswordWithSalt params@PBKDF2Params{..} s@(Salt salt) pass =
  PasswordHash $ T.intercalate ":"
    [ algToText pbkdf2Algorithm
    , T.pack $ show pbkdf2Iterations
    , b64 salt
    , b64 key
    ]
  where
    b64 = Base64.encodeBase64
    key = hashPasswordWithSalt' params s pass

-- | Only for internal use
hashPasswordWithSalt' :: PBKDF2Params -> Salt PBKDF2 -> Password -> ByteString
hashPasswordWithSalt' PBKDF2Params{..} (Salt salt) pass =
    convert (pbkdf2Hash :: Bytes)
  where
    pbkdf2Hash = algToFunc
        pbkdf2Algorithm
        params
        (toBytes $ unsafeShowPassword pass)
        (convert salt :: Bytes)
    params = PBKDF2.Parameters {
        PBKDF2.iterCounts = fromIntegral pbkdf2Iterations,
        PBKDF2.outputLength = fromIntegral $ maxOutputLength pbkdf2Algorithm pbkdf2OutputLength
      }

-- | Hash a password using the 'PBKDF2' algorithm with the given 'PBKDF2Params'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- 'PBKDF2' algorithm, please just use 'hashPassword'.
--
-- @since 2.0.0.0
hashPasswordWithParams :: MonadIO m => PBKDF2Params -> Password -> m (PasswordHash PBKDF2)
hashPasswordWithParams params pass = liftIO $ do
    salt <- Data.Password.Internal.newSalt . fromIntegral $ pbkdf2Salt params
    return $ hashPasswordWithSalt params salt pass

-- | Check a 'Password' against a 'PasswordHash' 'PBKDF2'.
--
-- Returns 'PasswordCheckSuccess' on success.
--
-- >>> let pass = mkPassword "foobar"
-- >>> passHash <- hashPassword pass
-- >>> checkPassword pass passHash
-- PasswordCheckSuccess
--
-- Returns 'PasswordCheckFail' if an incorrect 'Password' or 'PasswordHash' 'PBKDF2' is used.
--
-- >>> let badpass = mkPassword "incorrect-password"
-- >>> checkPassword badpass passHash
-- PasswordCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPasswordHash = hashPasswordWithSalt testParams salt "foobar" in checkPassword badpass correctPasswordHash == PasswordCheckFail
checkPassword :: Password -> PasswordHash PBKDF2 -> PasswordCheck
checkPassword pass (PasswordHash passHash) =
  fromMaybe PasswordCheckFail $ do
    -- This step makes it possible to also check the following format:
    -- "pbkdf2:sha256:150000:etc.etc."
    let passHash' = fromMaybe passHash $ "pbkdf2:" `T.stripPrefix` passHash
        paramList = T.split (== ':') passHash'
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
        producedKey = hashPasswordWithSalt' PBKDF2Params{..} (Salt salt) pass
    guard $ hashedKey `constEq` producedKey
    return PasswordCheckSuccess
  where
    pbkdf2Salt = 16


-- | Type of algorithm to use for hashing PBKDF2 passwords.
--
-- N.B.: 'PBKDF2_MD5' and 'PBKDF2_SHA1' are not considered very secure.
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
  "md5" -> Just PBKDF2_MD5
  "sha1" -> Just PBKDF2_SHA1
  "sha256" -> Just PBKDF2_SHA256
  "sha512" -> Just PBKDF2_SHA512
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
