{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

{-|
Module      : Data.Password.Valid
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020; Hiroto Shioi, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= validate

It is common for passwords to have a set of requirements.
(e.g. Password must contain at least eight characters that consist of alphabetic
characters combined with numbers or special characters.)

Validate module provides set of functions which enables you to validate them.

-}

module Data.Password.Validate
  ( -- * Data type
    PasswordPolicy (..),
    InvalidReason (..),
    CharacterCategory(..),
    -- * Predicate
    CharSetPredicate(..),
    -- * Default
    defaultPasswordPolicy,
    defaultCharSetPredicate,
    -- * Functions
    isValidPassword,
    validatePassword,
    -- * Utility
    isValidPasswordPolicy,
    isSpecial,
    defaultCharSet
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, isDigit, ord)
import Data.Maybe (catMaybes, fromMaybe, isJust)
import Data.Password.Internal (Password (..))
#if! MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

-- | Set of policies used to validate 'Password'
data PasswordPolicy = PasswordPolicy
    { minimumLength  :: !Int
    -- ^ Required password minimum length
    , maximumLength  :: !Int
    -- ^ Required password maximum length
    , uppercaseChars :: !(Maybe Int)
    -- ^ Required number of upper-case characters
    , lowercaseChars :: !(Maybe Int)
    -- ^ Required number of lower-case characters
    , specialChars   :: !(Maybe Int)
    -- ^ Required number of special characters
    , digitChars     :: !(Maybe Int)
    -- ^ Required number of ASCII-digit characters
    } deriving (Eq, Ord, Show)

-- | Default value for the 'PasswordPolicy'
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { minimumLength = 8,
    maximumLength = 32,
    uppercaseChars = Just 1,
    lowercaseChars = Just 1,
    specialChars = Nothing,
    digitChars = Just 1
  }

-- | Predicate which defines the characters that can be used for a password.
newtype CharSetPredicate = CharSetPredicate
  { getCharSetPredicate :: Char -> Bool
  }


-- | Default character sets consist of uppercase, lowercase letters, numbers,
-- and special characters
defaultCharSetPredicate :: CharSetPredicate
defaultCharSetPredicate =  CharSetPredicate $ \c -> ord c >= 32 && ord c <= 126

-- | Check if given 'Char' is special character
isSpecial :: Char -> Bool
isSpecial = \c ->
    isDefault c && not (or [isAsciiUpper c, isAsciiLower c, isDigit c])
  where
    CharSetPredicate isDefault = defaultCharSetPredicate

-- | Character Category
data CharacterCategory
  = Uppercase
  | Lowercase
  | Special
  | Digit
  deriving (Eq, Ord, Show)

-- | Possible reason of password being invalid
data InvalidReason
  = PasswordTooShort !Int !Int
  -- ^ Length of password is too short.
  --
  -- Expected at least 'Int' characters but the actual length is 'Int'
  | PasswordTooLong !Int !Int
  -- ^ Length of password is too long.
  --
  -- Expected at maximum of 'Int' characters, but the actual length is 'Int'
  | NotEnoughReqChars CharacterCategory !Int !Int
  -- ^ Password does not contain required number of characters.
  --
  -- Expected at least 'Int' characters of 'CharacterCategory' but the password only
  -- contains 'Int'
  | InvalidChar !Text
  -- ^ Password contains characters that cannot be used
  | InvalidPasswordPolicy !PasswordPolicy
  -- ^ 'PasswordPolicy' is invalid
  deriving (Eq, Ord, Show)


-- | Check if given 'Password' fullfills all the Policies,
-- return true if given password is valid
--
-- This is equivalent to @null $ validatePassword policy password@
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> isValidPassword defaultPasswordPolicy defaultCharSetPredicate pass
-- True
isValidPassword :: PasswordPolicy -> CharSetPredicate -> Password -> Bool
isValidPassword policy pre pass = null $ validatePassword policy pre pass
{-# INLINE isValidPassword #-}

-- | Check if given 'Password' fulfills all of the Policies, returns list of
-- reasons why it's invalid.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy defaultCharSetPredicate　pass
-- []
validatePassword :: PasswordPolicy -> CharSetPredicate -> Password -> [InvalidReason]
validatePassword passwordPolicy@PasswordPolicy{..} charSetPredicate (Password password) =
  catMaybes
    [ isValidPolicy,
      isTooShort,
      isTooLong,
      isUsingPolicyCharSetPredicate,
      hasRequiredChar uppercaseChars Uppercase,
      hasRequiredChar lowercaseChars Lowercase,
      hasRequiredChar specialChars Special,
      hasRequiredChar digitChars Digit
    ]
  where
    isValidPolicy :: Maybe InvalidReason
    isValidPolicy =
      if isValidPasswordPolicy passwordPolicy charSetPredicate
        then Nothing
        else Just $ InvalidPasswordPolicy passwordPolicy
    isTooLong :: Maybe InvalidReason
    isTooLong =
      if T.length password <= maximumLength
        then Nothing
        else Just $ PasswordTooLong maximumLength (T.length password)
    isTooShort :: Maybe InvalidReason
    isTooShort =
      if T.length password >= minimumLength
          then Nothing
          else Just $ PasswordTooShort minimumLength (T.length password)
    isUsingPolicyCharSetPredicate :: Maybe InvalidReason
    isUsingPolicyCharSetPredicate =
        let filteredText = T.filter (\c -> not $ (getCharSetPredicate charSetPredicate) c) password
        in if T.null filteredText
          then Nothing
          else Just $ InvalidChar filteredText
    hasRequiredChar :: Maybe Int -> CharacterCategory -> Maybe InvalidReason
    hasRequiredChar Nothing _ = Nothing
    hasRequiredChar (Just requiredCharNum) characterCategory =
      let predicate = case characterCategory of
            Uppercase -> isAsciiUpper
            Lowercase -> isAsciiLower
            Special   -> isSpecial
            Digit     -> isDigit
          actualRequiredCharNum = T.length $ T.filter predicate password
       in if actualRequiredCharNum >= requiredCharNum
          then Nothing
          else Just $ NotEnoughReqChars characterCategory requiredCharNum actualRequiredCharNum

-- | Checks if given 'PasswordPolicy' is valid
--
-- >>> isValidPasswordPolicy defaultPasswordPolicy defaultCharSetPredicate
-- True
isValidPasswordPolicy :: PasswordPolicy -> CharSetPredicate -> Bool
isValidPasswordPolicy PasswordPolicy{..} charSetPredicate =
  and
   [ max minimumLength sumRequiredChars <= maximumLength
   , minimumLength > 0
   , maximumLength > 0
   , isPositive uppercaseChars
   , isPositive lowercaseChars
   , isPositive specialChars
   , isPositive digitChars
   , requiredCharsetValid
   ]
  where
    isPositive :: Maybe Int -> Bool
    isPositive mNum = maybe True (> 0) mNum
    sumRequiredChars :: Int
    sumRequiredChars =
      sum $ fromMaybe 0 <$> [uppercaseChars, lowercaseChars, specialChars, digitChars]
    -- Check that if PasswordPolicy states that the passwords requires certain
    -- characters, then CharSetPredicate should return true on at least one of
    -- the characters that is required.
    requiredCharsetValid :: Bool
    requiredCharsetValid =
      let charSets = accumulateCharSet
            [ (uppercaseChars, isAsciiUpper)
            , (lowercaseChars, isAsciiLower)
            , (specialChars, isSpecial)
            , (digitChars, isDigit)
            ]
      in all (\str -> any (getCharSetPredicate charSetPredicate) str) charSets
    accumulateCharSet :: [(Maybe Int, Char -> Bool)] -> [String]
    accumulateCharSet = map (\t -> filter (snd t) defaultCharSet) . filter (isJust . fst)

defaultCharSet :: String
defaultCharSet = chr <$> [32 .. 126]
