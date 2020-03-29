{-# LANGUAGE CPP #-}
{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.Argon2
Copyright   : (c) Dennis Gosnell, Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX
-}

-- I think the portability is broadened to
-- whatever, now that we use cryptonite... I think
module Data.Password.Argon2 (
    Argon2
  -- * Hash Passwords (Argon2)
  , hashPass
  -- * Verify Passwords (Argon2)
  , checkPass
  -- * Hashing Manually (DISADVISED)
  --
  -- | If you have any doubt about what the parameters do or mean,
  -- please just use 'hashPass'.
  , hashPassWithParams
  , Argon2Params(..)
  , defaultParams
  , Argon2.Variant(..)
  , Argon2.Version(..)
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
import Crypto.Error (throwCryptoError)
import Crypto.KDF.Argon2 as Argon2
import Data.ByteArray (Bytes, convert)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Base64 as Base64
import qualified Data.ByteString.Char8 as C8 (length)
import Data.Maybe (fromMaybe)
import Data.Password.Internal hiding (newSalt)
import qualified Data.Password.Internal
#if MIN_VERSION_base(4,9,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T (intercalate, length, pack, split, splitAt, unpack)
import Data.Text.Encoding (encodeUtf8)
import Data.Word (Word32)
import Text.Read (readMaybe)

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
-- >>> import Data.Password
-- >>> import Data.ByteString (pack)
-- >>> import Test.QuickCheck (Arbitrary(arbitrary), Blind(Blind), vector)
-- >>> import Test.QuickCheck.Instances.Text ()
--
-- >>> instance Arbitrary (Salt a) where arbitrary = Salt . pack <$> vector 16
-- >>> instance Arbitrary Pass where arbitrary = fmap Pass arbitrary
-- >>> let testParams = defaultParams {argon2TimeCost = 1}
-- >>> instance Arbitrary (PassHash Argon2) where arbitrary = hashPassWithSalt testParams <$> arbitrary <*> arbitrary

-- | Hash the 'Pass' using the /Argon2/ hash algorithm
--
-- >>> hashPass $ mkPass "foobar"
-- PassHash {unPassHash = "$argon2id$v=19$m=65536,t=2,p=1$...$..."}
hashPass :: MonadIO m => Pass -> m (PassHash Argon2)
hashPass = hashPassWithParams defaultParams

-- | Parameters used in the /Argon2/ hashing algorithm.
--
-- @since 2.0.0.0
data Argon2Params = Argon2Params {
  argon2Salt :: Word32,
  -- ^ Bytes to randomly generate as a unique salt, default is __16__
  --
  -- Limits are min: @8@, and max: @2 ^ 32 -1@
  argon2Variant :: Argon2.Variant,
  -- ^ Which variant of Argon2 to use ('Argon2d', 'Argon2i' or 'Argon2id')
  argon2Version :: Argon2.Version,
  -- ^ Which version of Argon2 to use ('Version10' or 'Version13')
  argon2MemoryCost :: Word32,
  -- ^ Memory cost, default is __65536__ (i.e. 64MB)
  --
  -- Limits are min: @8 * 'argon2Parallelism'@, and max is addressing
  -- space / 2, or @2 ^ 32 - 1@, whichever is lower.
  argon2TimeCost :: Word32,
  -- ^ Amount of computation realized, default is __2__
  --
  -- Limits are min: @1@, and max: @2 ^ 32 - 1@
  argon2Parallelism :: Word32,
  -- ^ Parallelism factor, default is __1__
  --
  -- Limits are min: @1@, and max: @2 ^ 24 - 1@
  argon2OutputLength :: Word32
  -- ^ Output key length in bytes, default is __32__
  --
  -- Limits are min: @4@, and max: @2 ^ 32 - 1@
} deriving (Eq, Show)

-- | Default parameters for the /Argon2/ algorithm.
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
-- instead of a random generated salt using 'argon2Salt' from 'Argon2Params'. (cf. 'hashPassWithParams')
-- Using 'hashPassWithSalt' is strongly disadvised and 'hashPassWithParams' should be used instead.
-- /Never use a static salt in production applications!/
--
-- __N.B.__: The salt HAS to be 8 bytes or more, or this function will throw an error!
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPassWithSalt defaultParams salt (mkPass "foobar")
-- PassHash {unPassHash = "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA==$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o="}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'. 'hashPass'
-- generates a new 'Salt' everytime it is called.)
hashPassWithSalt :: Argon2Params -> Salt Argon2 -> Pass -> PassHash Argon2
hashPassWithSalt params@Argon2Params{..} s@(Salt salt) pass =
  PassHash . mappend "$argon2" $ T.intercalate "$"
    [ variantToLetter argon2Variant
    , "v=" <> versionToNum argon2Version
    , parameters
    , b64 salt
    , b64 key
    ]
  where
    t :: forall a. Show a => a -> Text
    t = T.pack . show
    b64 = Base64.encodeBase64
    parameters = T.intercalate ","
        [ "m=" <> t argon2MemoryCost
        , "t=" <> t argon2TimeCost
        , "p=" <> t argon2Parallelism
        ]
    key = hashPassWithSalt' params s pass

-- | Only for internal use
hashPassWithSalt' :: Argon2Params -> Salt Argon2 -> Pass -> ByteString
hashPassWithSalt' Argon2Params{..} (Salt salt) (Pass pass) =
    convert (argon2Hash :: Bytes)
  where
    argon2Hash = throwCryptoError $
        Argon2.hash options (toBytes pass) (convert salt :: Bytes) $ fromIntegral argon2OutputLength
    options = Argon2.Options {
        iterations = argon2TimeCost,
        memory = argon2MemoryCost,
        parallelism = argon2Parallelism,
        variant = argon2Variant,
        version = argon2Version
      }

-- | Hash a password using the /Argon2/ algorithm with the given 'Argon2Params'.
--
-- __N.B.__: If you have any doubt in your knowledge of cryptography and/or the
-- /Argon2/ algorithm, please just use 'hashPass'.
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
hashPassWithParams :: MonadIO m => Argon2Params -> Pass -> m (PassHash Argon2)
hashPassWithParams params pass = liftIO $ do
    salt <- Data.Password.Internal.newSalt . fromIntegral $ argon2Salt params
    return $ hashPassWithSalt params salt pass

-- | Check a 'Pass' against a 'PassHash' 'Argon2'.
--
-- Returns 'PassCheckSuccess' on success.
--
-- >>> let pass = mkPass "foobar"
-- >>> passHash <- hashPass pass
-- >>> checkPass pass passHash
-- PassCheckSuccess
--
-- Returns 'PassCheckFail' if an incorrect 'Pass' or 'PassHash' 'Argon2' is used.
--
-- >>> let badpass = mkPass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPassHash = hashPassWithSalt testParams salt "foobar" in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash Argon2 -> PassCheck
checkPass pass (PassHash passHash) =
  fromMaybe PassCheckFail $ do
    let paramList = T.split (== '$') passHash
    guard $ length paramList == 6
    let [ _,
          variantT,
          versionT,
          parametersT,
          salt64,
          hashedKey64 ] = paramList
    argon2Variant <- parseVariant variantT
    argon2Version <- parseVersion versionT
    (argon2MemoryCost, argon2TimeCost, argon2Parallelism) <- parseParameters parametersT
    salt <- from64 salt64
    hashedKey <- from64 hashedKey64
    let argon2OutputLength = fromIntegral $ C8.length hashedKey -- only here because of warnings
        producedKey = hashPassWithSalt' Argon2Params{..} (Salt salt) pass
    guard $ hashedKey == producedKey
    return PassCheckSuccess
  where
    argon2Salt = 16 -- only here because of warnings
    from64 = either (\_ -> Nothing) pure . Base64.decodeBase64 . encodeUtf8
    parseVariant = splitMaybe "argon2" letterToVariant
    parseVersion = splitMaybe "v=" numToVersion
    parseParameters params = do
        let ps = T.split (== ',') params
        guard $ length ps == 3
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
    readT :: forall a. Read a => Text -> Maybe a
    readT = readMaybe . T.unpack

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
