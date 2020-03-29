{-|
Module      : Data.Password
Copyright   : (c) Dennis Gosnell, 2019
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

This library provides an easy way for interacting with passwords from Haskell.
It provides the types 'Pass' and 'PassHash', which correspond to plain-text and
hashed passwords.

Every supported hashing algorithm has its own module (e.g. "Data.Password.BCrypt")
which exports its own @hashPass@ and @checkPass@ functions, as well as all the
types and functions in this module. If you are not sure about the specifics of an
algorithm you want to use, you can rest assured that by using the @hashPass@ function
of the respective algorithm you are not making any big mistakes, security-wise.

Of course, if you know what you're doing and you want more fine-grained control
over the hashing function, you can adjust it using the @hashPassWithParams@
function of the respective algorithm.


The real benefit of this module is that there is a corresponding
<http://hackage.haskell.org/package/password-instances password-instances>
module that provides canonical typeclass instances for
'Pass' and 'PassHash' for many common typeclasses, like
<http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON FromJSON> from
<http://hackage.haskell.org/package/aeson aeson>,
<http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistField PersistField>
from
<http://hackage.haskell.org/package/persistent persistent>, etc.

See the <http://hackage.haskell.org/package/password-instances password-instances> module for more information.
-}

module Data.Password (
    -- * Plaintext Password
    Pass
  , mkPass
    -- * Password Hashing
  , PassHash(..)
  , PassCheck(..)
  , Salt(..)
  , newSalt
    -- * Unsafe Debugging Functions for Showing a Password
  , unsafeShowPassword
  , unsafeShowPasswordText
  ) where

import Data.Password.Internal

-- TODO: Create code for checking that plaintext passwords conform to some sort of
-- password policy.

-- data PassPolicy = PassPolicy
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
