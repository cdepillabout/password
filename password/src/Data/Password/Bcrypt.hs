{-|
Module      : Data.Password.Bcrypt
Copyright   : (c) Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= bcrypt

The @bcrypt@ algorithm is a popular way of hashing passwords.
It is based on the Blowfish cipher and fairly straightfoward
in its usage. It has a cost parameter that, when increased,
slows down the hashing speed.

It is a straightforward and easy way to get decent protection
on passwords, it has also been around long enough to be battle-tested
and generally considered to provide a good amount of security.

== Other algorithms

@bcrypt@, together with @'Data.Password.PBKDF2.PBKDF2'@, are only computationally intensive.
And to protect from specialized hardware, new algorithms have been
developed that are also resource intensive, like @'Data.Password.Scrypt.Scrypt'@ and
@'Data.Password.Argon2.Argon2'@. Not having high resource demands, means an attacker with
specialized software could take less time to brute-force a password,
though with the default cost (10) and a decently long password,
the amount of time to brute-force would still be significant.

This the algorithm to use if you're not sure about your needs, but
just want a decent, proven way to encrypt your passwords.
-}

module Data.Password.Bcrypt (
  -- * Algorithm
  Bcrypt
  -- * Plain-text Password
  , Password
  , mkPassword
  -- * Hash Passwords (bcrypt)
  , hashPassword
  , PasswordHash(..)
  -- * Verify Passwords (bcrypt)
  , checkPassword
  , PasswordCheck(..)
  -- * Hashing Manually (bcrypt)
  , hashPasswordWithParams
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

import Control.Monad.IO.Class (MonadIO(liftIO))
import Crypto.KDF.BCrypt as Bcrypt (bcrypt, validatePassword)
import Data.ByteArray (Bytes, convert)

import Data.Password.Types (
    Password
  , PasswordHash(..)
  , mkPassword
  , unsafeShowPassword
  , Salt(..)
  )
import Data.Password.Internal (
    PasswordCheck(..)
  , fromBytes
  , toBytes
  )
import qualified Data.Password.Internal (newSalt)


-- | Phantom type for __bcrypt__
--
-- @since 2.0.0.0
data Bcrypt

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
-- >>> let salt = Salt "abcdefghijklmnop"

-- -- >>> instance Arbitrary (PasswordHash Bcrypt) where arbitrary = hashPasswordWithSalt 8 <$> arbitrary <*> arbitrary

-- | Hash the 'Password' using the /bcrypt/ hash algorithm.
--
-- __N.B.__: @bcrypt@ has a limit of 72 bytes as input, so anything longer than that
-- will be cut off at the 72 byte point and thus any password that is 72 bytes
-- or longer will match as long as the first 72 bytes are the same.
--
-- >>> hashPassword $ mkPassword "foobar"
-- PasswordHash {unPasswordHash = "$2b$10$..."}
hashPassword :: MonadIO m => Password -> m (PasswordHash Bcrypt)
hashPassword = hashPasswordWithParams 10

-- | Hash a password with the given cost and also with the given 'Salt'
-- instead of generating a random salt. Using 'hashPasswordWithSalt' is strongly __disadvised__,
-- and 'hashPasswordWithParams' should be used instead. /Never use a static salt/
-- /in production applications!/
--
-- __N.B.__: The salt HAS to be 16 bytes or this function will throw an error!
--
-- >>> let salt = Salt "abcdefghijklmnop"
-- >>> hashPasswordWithSalt 10 salt (mkPassword "foobar")
-- PasswordHash {unPasswordHash = "$2b$10$WUHhXETkX0fnYkrqZU3ta.N8Utt4U77kW4RVbchzgvBvBBEEdCD/u"}
--
-- (Note that we use an explicit 'Salt' in the example above.  This is so that the
-- example is reproducible, but in general you should use 'hashPassword'. 'hashPassword'
-- (and 'hashPasswordWithParams') generates a new 'Salt' everytime it is called.)
hashPasswordWithSalt
  :: Int -- ^ The cost parameter. Should be between 4 and 31 (inclusive). Values which lie outside this range will be adjusted accordingly.
  -> Salt Bcrypt -- ^ The salt. MUST be 16 bytes in length or an error will be raised.
  -> Password -- ^ The password to be hashed.
  -> PasswordHash Bcrypt -- ^ The bcrypt hash in standard format.
hashPasswordWithSalt cost (Salt salt) pass =
    let hash = Bcrypt.bcrypt
            cost
            (convert salt :: Bytes)
            (toBytes $ unsafeShowPassword pass)
    in PasswordHash $ fromBytes hash

-- | Hash a password using the /bcrypt/ algorithm with the given cost.
--
-- The higher the cost, the longer 'hashPassword' and 'checkPassword' will take to run,
-- thus increasing the security, but taking longer and taking up more resources.
-- The optimal cost for generic user logins would be one that would take between
-- 0.05 - 0.5 seconds to check on the machine that will run it.
--
-- __N.B.__: It is advised to use 'hashPassword' if you're unsure about the
-- implications that changing the cost brings with it.
--
-- @since 2.0.0.0
hashPasswordWithParams
  :: MonadIO m
  => Int -- ^ The cost parameter. Should be between 4 and 31 (inclusive). Values which lie outside this range will be adjusted accordingly.
  -> Password -- ^ The password to be hashed.
  -> m (PasswordHash Bcrypt) -- ^ The bcrypt hash in standard format.
hashPasswordWithParams cost pass = liftIO $ do
    salt <- newSalt
    return $ hashPasswordWithSalt cost salt pass

-- | Check a 'Password' against a 'PasswordHash' 'Bcrypt'.
--
-- Returns 'PasswordCheckSuccess' on success.
--
-- >>> let pass = mkPassword "foobar"
-- >>> passHash <- hashPassword pass
-- >>> checkPassword pass passHash
-- PasswordCheckSuccess
--
-- Returns 'PasswordCheckFail' if an incorrect 'Password' or 'PasswordHash' 'Bcrypt' is used.
--
-- >>> let badpass = mkPassword "incorrect-password"
-- >>> checkPassword badpass passHash
-- PasswordCheckFail
--
-- This should always fail if an incorrect password is given.
--
-- prop> \(Blind badpass) -> let correctPasswordHash = hashPasswordWithSalt 8 salt "foobar" in checkPassword badpass correctPasswordHash == PasswordCheckFail
checkPassword :: Password -> PasswordHash Bcrypt -> PasswordCheck
checkPassword pass (PasswordHash passHash) =
    if Bcrypt.validatePassword
        (toBytes $ unsafeShowPassword pass)
        (toBytes passHash)
      then PasswordCheckSuccess
      else PasswordCheckFail

-- | Generate a random 16-byte @bcrypt@ salt
--
-- @since 2.0.0.0
newSalt :: MonadIO m => m (Salt Bcrypt)
newSalt = Data.Password.Internal.newSalt 16
