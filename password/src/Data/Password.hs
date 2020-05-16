{-|
Module      : Data.Password
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This library provides an easy way for interacting with passwords from Haskell.
It provides the types 'Password' and 'PasswordHash', which correspond to plain-text and
hashed passwords.

== API

Every supported hashing algorithm has its own module (e.g. "Data.Password.Bcrypt")
which exports its own @hashPassword@ and @checkPassword@ functions, as well as all the
types and functions in this module. If you are not sure about the specifics of an
algorithm you want to use, you can rest assured that by using the @hashPassword@ function
of the respective algorithm you are not making any big mistakes, security-wise.

Of course, if you know what you're doing and you want more fine-grained control
over the hashing function, you can adjust it using the @hashPasswordWithParams@
function of the respective algorithm.

== Algorithms

Generally, the most "secure" algorithm is believed to be @'Data.Password.Argon2.Argon2'@,
then @'Data.Password.Scrypt.Scrypt'@, then @'Data.Password.Bcrypt.Bcrypt'@, and lastly
@'Data.Password.PBKDF2.PBKDF2'@. @'Data.Password.Bcrypt.Bcrypt'@
and @'Data.Password.PBKDF2.PBKDF2'@ are the most established algorithms, so they have
been tried and tested, though they both lack a memory cost, and therefore have a
greater vulnerability to specialized hardware attacks.

When choosing an algorithm, and you have no idea which to pick, just go for
@'Data.Password.Bcrypt.Bcrypt'@ if your password does not need the highest security possible.
It's still a fine way for hashing passwords, and the cost is easily adjustable if needed.
If your needs do require stronger protection, you should find someone who can advise you
on this topic. (And if you're already knowledgeable enough, you know what to do)

== Special instances

The real benefit of this module is that there is an accompanying
<http://hackage.haskell.org/package/password-instances password-instances>
package that provides canonical typeclass instances for
'Password' and 'PasswordHash' for many common typeclasses, like
<http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON FromJSON> from
<http://hackage.haskell.org/package/aeson aeson>,
<http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistField PersistField>
from
<http://hackage.haskell.org/package/persistent persistent>, etc.

See the <http://hackage.haskell.org/package/password-instances password-instances> package for more information.
-}

module Data.Password (
    -- * Plain-text Password
    Password
  , mkPassword
    -- * Password Hashing
  , PasswordHash(..)
  , PasswordCheck(..)
  , Salt(..)
  , newSalt
    -- * Unsafe debugging function to show a Password
  , unsafeShowPassword
  ) where

import Data.Password.Internal

-- TODO: Create code for checking that plain-text passwords conform to some sort of
-- password policy.

-- data PasswordPolicy = PasswordPolicy
--   { passPolicyLength :: Int
--   , passPolicyCharReqs :: [PolicyCharReq]
--   , passPolicyCharSet :: PolicyCharSet
--   }

-- -- | Character requirements for a password policy.
-- data PolicyCharReq
--   = PolicyCharReqUpper Int
--   -- ^ A password requires at least 'Int' upper-case characters.
--   | PolicyCharReqLower Int
--   -- ^ A password requires at least 'Int' lower-case characters.
--   | PolicyCharReqSpecial Int
--   -- ^ A password requires at least 'Int' special characters

-- data PolicyCharSet = PolicyCharSetAscii
