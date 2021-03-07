{-# LANGUAGE CPP #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.Argon2
Copyright   : (c) Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= Argon2

@Argon2@ is probably the newest password algorithm out there. Argon2 was
selected as the winner of the Password Hashing Competition in July 2015.

It has three variants, namely 'Argon2d', 'Argon2i' and 'Argon2id'. These protect
against GPU cracking attacks, side-channel attacks, and both, respectively.

All three modes allow specification by three parameters that control:

* execution time
* memory required
* degree of parallelism

== Other algorithms

In comparison to other algorithms, Argon2 is the least "battle-tested",
being the newest algorithm out there.

It is, however, recommended over @'Data.Password.Scrypt.Scrypt'@ most of the time,
and it also seems like it might become the go-to password algorithm if no
vulnarabilities are discovered within the next couple of years.
-}

-- I think the portability is broadened to
-- whatever, now that we use cryptonite... I think
module Data.Password.Argon2 (
  -- Algorithm
  Argon2
  -- * Plain-text Password
  , Password
  , mkPassword
  -- * Hash Passwords (Argon2)
  , hashPassword
  , PasswordHash(..)
  -- * Verify Passwords (Argon2)
  , checkPassword
  , PasswordCheck(..)
  -- * Hashing Manually (Argon2)
  , hashPasswordWithParams
  , defaultParams
  , Argon2Params(..)
  , Argon2.Variant(..)
  , Argon2.Version(..)
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
import Control.Monad.IO.Class (MonadIO (liftIO))
import Crypto.Error (throwCryptoError)
import Crypto.KDF.Argon2 as Argon2 (Options (..), Variant (..), Version (..), hash)
import Data.ByteArray (Bytes, constEq, convert)
import Data.ByteString as B (ByteString, length)
import Data.ByteString.Base64 (encodeBase64)
import Data.Maybe (fromMaybe)
#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T (intercalate, length, split, splitAt)
import Data.Word (Word32)

import Data.Password.Internal (
    PasswordCheck (..),
    from64,
    readT,
    showT,
    toBytes,
    unsafePad64,
    unsafeRemovePad64,
 )
import Data.Password.Types (
    Password,
    PasswordHash (..),
    Salt (..),
    mkPassword,
    unsafeShowPassword,
 )
import qualified Data.Password.Internal (newSalt)


-- | Phantom type for __Argon2__
--
-- @since 2.0.0.0
data Argon2

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
-- >>> let testParams = defaultParams {argon2TimeCost = 1}
-- >>> let salt = Salt "abcdefghijklmnop"

-- -- >>> instance Arbitrary (PasswordHash Argon2) where arbitrary = hashPasswordWithSalt testParams <$> arbitrary <*> arbitrary

-- | Hash the 'Password' using the 'Argon2' hash algorithm
--
-- >>> hashPassword $ mkPassword "foobar"
-- PasswordHash {unPasswordHash = "$argon2id$v=19$m=65536,t=2,p=1$...$..."}
hashPassword :: MonadIO m => Password -> m (PasswordHash Argon2)
hashPassword = hashPasswordWithParams defaultParams

-- | Parameters used in the 'Argon2' hashing algorithm.
--
-- @since 2.0.0.0
data Argon2Params = Argon2Params {
  argon2Salt :: Word32,
  -- ^ Bytes to randomly generate as a unique salt, default is __16__
  --
  -- Limits are min: @8@, and max: @(2 ^ 32) - 1@
  argon2Variant :: Argon2.Variant,
  -- ^ Which variant of Argon2 to use, default is __'Argon2id'__
  argon2Version :: Argon2.Version,
  -- ^ Which version of Argon2 to use, default is __'Version13'__
  argon2MemoryCost :: Word32,
  -- ^ Memory cost, given in /kibibytes/, default is __65536__ (i.e. 64MB)
  --
  -- Limits are min: @8 * 'argon2Parallelism'@, and max is addressing
  -- space / 2, or @(2 ^ 32) - 1@, whichever is lower.
  argon2TimeCost :: Word32,
  -- ^ Amount of computation realized, default is __2__
  --
  -- Limits are min: @1@, and max: @(2 ^ 32) - 1@
  argon2Parallelism :: Word32,
  -- ^ Parallelism factor, default is __1__
  --
  -- Limits are min: @1@, and max: @(2 ^ 24) - 1@
  argon2OutputLength :: Word32
  -- ^ Output key length in bytes, default is __32__
  --
  -- Limits are min: @4@, and max: @(2 ^ 32) - 1@
} deriving (Eq, Show)

-- | Default parameters for the 'Argon2' algorithm.
--
-- >>> defaultParams
-- Argon2Params {argon2Salt = 16, argon2Variant = Argon2id, argon2Version = Version13, argon2MemoryCost = 65536, argon2TimeCost = 2, argon2Parallelism = 1, argon2OutputLength = 32}
--
-- @since 2.0.0.0
defaultParams :: Argon2Params
defaultParams = Argon2Params {
  argon2Salt = 16,
  argon2Variant = Argon2id,
  argon2Version = Version13,
  argon2MemoryCost = 2 ^ (16 :: Int),
  argon2TimeCost = 2,
  argon2Parallelism = 1,
  argon2OutputLength = 32
}

-- | Hash a password with the given 'Argon2Params' and also with the given 'Salt'
-- instead of a random generated salt using 'argon2Salt' from 'Argon2Params'. (cf. 'hashPasswordWithParams')
-- Using 'hashPasswordWithSalt' is strongly __disadvised__ and 'hashPasswordWithParams' should be used instead.
-- /Never use a static salt in production applications!/
--
-- __N.B.__: The salt HAS to be 8 bytes or more, or this function will throw an error!
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPasswordWithSalt defaultParams salt (mkPassword "foobar")
-- PasswordHash {unPasswordHash = "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o"}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPassword'. 'hashPassword'
-- generates a new 'Salt' everytime it is called.)
hashPasswordWithSalt :: Argon2Params -> Salt Argon2 -> Password -> PasswordHash Argon2
hashPasswordWithSalt params@Argon2Params{..} s@(Salt salt) pass =
  PasswordHash . mappend "$argon2" $ T.intercalate "$"
    [ variantToLetter argon2Variant
    , "v=" <> versionToNum argon2Version
    , parameters
    , encodeWithoutPadding salt
    , encodeWithoutPadding key
    ]
  where
    encodeWithoutPadding bs =
        unsafeRemovePad64 (B.length bs) $ encodeBase64 bs
    parameters = T.intercalate ","
        [ "m=" <> showT argon2MemoryCost
        , "t=" <> showT argon2TimeCost
        , "p=" <> showT argon2Parallelism
        ]
    key = hashPasswordWithSalt' params s pass

-- | Only for internal use
hashPasswordWithSalt' :: Argon2Params -> Salt Argon2 -> Password -> ByteString
hashPasswordWithSalt' Argon2Params{..} (Salt salt) pass =
    convert (argon2Hash :: Bytes)
  where
    argon2Hash = throwCryptoError $
        Argon2.hash
            options
            (toBytes $ unsafeShowPassword pass)
            (convert salt :: Bytes)
            $ fromIntegral argon2OutputLength
    options = Argon2.Options {
        iterations = argon2TimeCost,
        memory = argon2MemoryCost,
        parallelism = argon2Parallelism,
        variant = argon2Variant,
        version = argon2Version
      }

-- | Hash a password using the 'Argon2' algorithm with the given 'Argon2Params'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- 'Argon2' algorithm, please just use 'hashPassword'.
--
-- Advice to set the parameters:
--
-- * Figure out how many threads you can use, choose "parallelism" accordingly.
-- * Figure out how much memory you can use, choose "memory cost" accordingly.
-- * Decide on the maximum time @x@ you can spend on it, choose the largest
-- "time cost" such that it takes less than @x@ with your system and other
-- parameter choices.
--
-- @since 2.0.0.0
hashPasswordWithParams :: MonadIO m => Argon2Params -> Password -> m (PasswordHash Argon2)
hashPasswordWithParams params pass = liftIO $ do
    salt <- Data.Password.Internal.newSalt . fromIntegral $ argon2Salt params
    return $ hashPasswordWithSalt params salt pass

-- TODO: Parse different kinds of hashes, not only the ones from this library.
-- e.g. hashes that miss the first $, or have 'argon2$' in front of the 'argon2id' part.

-- | Check a 'Password' against a 'PasswordHash' 'Argon2'.
--
-- Returns 'PasswordCheckSuccess' on success.
--
-- >>> let pass = mkPassword "foobar"
-- >>> passHash <- hashPassword pass
-- >>> checkPassword pass passHash
-- PasswordCheckSuccess
--
-- Returns 'PasswordCheckFail' if an incorrect 'Password' or 'PasswordHash' 'Argon2' is used.
--
-- >>> let badpass = mkPassword "incorrect-password"
-- >>> checkPassword badpass passHash
-- PasswordCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPasswordHash = hashPasswordWithSalt testParams salt "foobar" in checkPassword badpass correctPasswordHash == PasswordCheckFail
checkPassword :: Password -> PasswordHash Argon2 -> PasswordCheck
checkPassword pass (PasswordHash passHash) =
  fromMaybe PasswordCheckFail $ do
    let paramList = T.split (== '$') passHash
    guard $ Prelude.length paramList == 6
    let [ _,
          variantT,
          versionT,
          parametersT,
          salt64,
          hashedKey64 ] = paramList
    argon2Variant <- parseVariant variantT
    argon2Version <- parseVersion versionT
    (argon2MemoryCost, argon2TimeCost, argon2Parallelism) <- parseParameters parametersT
    salt <- from64 $ unsafePad64 salt64
    hashedKey <- from64 $ unsafePad64 hashedKey64
    let argon2OutputLength = fromIntegral $ B.length hashedKey -- only here because of warnings
        producedKey = hashPasswordWithSalt' Argon2Params{..} (Salt salt) pass
    guard $ hashedKey `constEq` producedKey
    return PasswordCheckSuccess
  where
    argon2Salt = 16 -- only here because of warnings
    parseVariant = splitMaybe "argon2" letterToVariant
    parseVersion = splitMaybe "v=" numToVersion
    parseParameters params = do
        let ps = T.split (== ',') params
        guard $ Prelude.length ps == 3
        go ps (Nothing, Nothing, Nothing)
      where
        go [] (Just m, Just t, Just p) = Just (m, t, p)
        go [] _ = Nothing
        go (x:xs) (m, t, p) =
          case T.splitAt 2 x of
            ("m=", i) -> go xs (readT i, t, p)
            ("t=", i) -> go xs (m, readT i, p)
            ("p=", i) -> go xs (m, t, readT i)
            _ -> Nothing
    splitMaybe :: Text -> (Text -> Maybe a) -> Text -> Maybe a
    splitMaybe match f t =
      case T.splitAt (T.length match) t of
        (m, x) | m == match -> f x
        _  -> Nothing

-- | Generate a random 16-byte @Argon2@ salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt Argon2)
newSalt = Data.Password.Internal.newSalt 16

-- | Makes a letter out of the variant
variantToLetter :: Argon2.Variant -> Text
variantToLetter = \case
    Argon2i  -> "i"
    Argon2d  -> "d"
    Argon2id -> "id"

-- | Parses the variant parameter in the encoded hash
letterToVariant :: Text -> Maybe Argon2.Variant
letterToVariant = \case
    "i"  -> Just Argon2i
    "d"  -> Just Argon2d
    "id" -> Just Argon2id
    _ -> Nothing

-- | Parses the "v=" parameter in the encoded hash
numToVersion :: Text -> Maybe Argon2.Version
numToVersion "16" = Just Argon2.Version10
numToVersion "19" = Just Argon2.Version13
numToVersion _ = Nothing

-- | Makes number for the "v=" parameter in the encoded hash
versionToNum :: Argon2.Version -> Text
versionToNum Version10 = "16"
versionToNum Version13 = "19"
