{-# LANGUAGE ExplicitForAll #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}
{-|
Module      : Data.Password.Bcrypt
Copyright   : (c) Dennis Gosnell, Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX
-}
-- I think the portability is broadened to
-- whatever, now that we use cryptonite... I think
module Data.Password.Bcrypt (
    Bcrypt
  -- * Hash Passwords (bcrypt)
  , hashPass
  -- * Verify Passwords (bcrypt)
  , checkPass
  -- * Hashing Manually (DISADVISED)
  --
  -- If you have any doubt about what the cost does or means,
  -- please, please just use 'hashPass'.
  , hashPassWithParams
  , hashPassWithSalt
  , newSalt
  ) where

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.KDF.BCrypt as Bcrypt
import Data.ByteArray (Bytes, convert)
import Data.Password.Internal hiding (newSalt)
import qualified Data.Password.Internal

-- | Phantom type for keeping 'PassHash'es apart
--
-- @since 2.0.0.0
data Bcrypt

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
-- >>> instance Arbitrary (PassHash Bcrypt) where arbitrary = hashPassWithSalt 8 <$> arbitrary <*> arbitrary

-- | Hash the 'Pass' using the /bcrypt/ hash algorithm.
--
-- >>> hashPass $ mkPass "foobar"
-- PassHash {unPassHash = "$2b$12$..."}
hashPass :: MonadIO m => Pass -> m (PassHash Bcrypt)
hashPass = hashPassWithParams 12

-- | Hash a password with the given cost and also with the given 'Salt'
-- instead of generating a random salt. Using 'hashPassWithSalt' is strongly disadvised,
-- and 'hashPassWithParams' should be used instead. /Never use a static salt/
-- /in production applications!/
--
-- __N.B.__: The salt HAS to be 16 bytes or this function will throw an error!
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPassWithSalt 10 salt (mkPass "foobar")
-- PassHash {unPassHash = "$2b$10$WUHhXETkX0fnYkrqZU3ta.N8Utt4U77kW4RVbchzgvBvBBEEdCD/u"}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPass'. 'hashPass'
-- (and 'hashPassWithParams') generates a new 'Salt' everytime it is called.)
hashPassWithSalt
  :: Int -- ^ The cost parameter. Should be between 4 and 31 (inclusive). Values which lie outside this range will be adjusted accordingly.
  -> Salt Bcrypt -- ^ The salt. MUST be 16 bytes in length or an error will be raised.
  -> Pass -- ^ The password to be hashed.
  -> PassHash Bcrypt -- ^ The bcrypt hash in standard format.
hashPassWithSalt cost (Salt salt) (Pass pass) =
    let hash = Bcrypt.bcrypt cost (convert salt :: Bytes) (toBytes pass)
    in PassHash $ fromBytes hash

-- | Hash a password using the /bcrypt/ algorithm with the given cost.
--
-- The higher the cost, the longer 'hashPass' and 'checkPass' will take, thus
-- increasing the security, but taking longer and taking up more resources.
-- The optimal cost for generic user logins would be one that would take around
-- 0.5 seconds to check on the machine that will run it.
--
-- __N.B.__: It is advised to use 'hashPass' if you're unsure about the
-- implications that changing the cost brings with it.
--
-- @since 2.0.0.0
hashPassWithParams
  :: MonadIO m
  => Int -- ^ The cost parameter. Should be between 4 and 31 (inclusive). Values which lie outside this range will be adjusted accordingly.
  -> Pass -- ^ The password to be hashed.
  -> m (PassHash Bcrypt) -- ^ The bcrypt hash in standard format.
hashPassWithParams cost pass = liftIO $ do
    salt <- newSalt
    return $ hashPassWithSalt cost salt pass

-- | Check a 'Pass' against a 'PassHash' 'Bcrypt'.
--
-- Returns 'PassCheckSuccess' on success.
--
-- >>> let pass = mkPass "foobar"
-- >>> passHash <- hashPass pass
-- >>> checkPass pass passHash
-- PassCheckSuccess
--
-- Returns 'PassCheckFail' if an incorrect 'Pass' or 'PassHash' 'Bcrypt' is used.
--
-- >>> let badpass = mkPass "incorrect-password"
-- >>> checkPass badpass passHash
-- PassCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPassHash = hashPassWithSalt 8 salt "foobar" in checkPass badpass correctPassHash == PassCheckFail
checkPass :: Pass -> PassHash Bcrypt -> PassCheck
checkPass (Pass pass) (PassHash passHash) =
    if Bcrypt.validatePassword (toBytes pass) (toBytes passHash)
      then PassCheckSuccess
      else PassCheckFail

-- | Generate a random 16-byte salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt Bcrypt)
newSalt = Data.Password.Internal.newSalt 16
