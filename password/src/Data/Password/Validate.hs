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
    -- * Default values
    defaultPasswordPolicy,
    defaultCharSetPredicate,
    -- * Functions
    isValidPassword,
    validatePassword,
    -- * For internal use
    isValidPasswordPolicy,
    isSpecial,
    defaultCharSet,
    categoryToPredicate
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, isDigit, ord)
import Data.Maybe (catMaybes, fromMaybe)
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
  -- ^ Uppercase letters
  | Lowercase
  -- ^ Lowercase letters
  | Special
  -- ^ Special characters
  | Digit
  -- ^ ASCII digits
  deriving (Eq, Ord, Show)

-- | Convert 'CharacterCategory' into associated predicate function
categoryToPredicate :: CharacterCategory -> (Char -> Bool)
categoryToPredicate = \case
  Uppercase -> isAsciiUpper
  Lowercase -> isAsciiLower
  Special -> isSpecial
  Digit -> isDigit

-- | Possible reason of password being invalid
data InvalidReason
  = PasswordTooShort !Int !Int
  -- ^ Length of 'Password' is too short.
  --
  -- Expected at least 'Int' characters but the actual length is 'Int'
  | PasswordTooLong !Int !Int
  -- ^ Length of 'Password' is too long.
  --
  -- Expected at maximum of 'Int' characters, but the actual length is 'Int'
  | NotEnoughReqChars CharacterCategory !Int !Int
  -- ^ 'Password' does not contain required number of characters.
  --
  -- Expected at least 'Int' characters of 'CharacterCategory' but the password only
  -- contains 'Int'
  | InvalidCharacters !Text
  -- ^ 'Password' contains characters that cannot be used
  | InvalidLength !Int !Int
  -- ^ Value of 'minimumLength' is bigger than 'maximumLength'
  | MaxLengthBelowZero !Int
  -- ^ Value of 'maximumLength' is less than zero
  | InvalidCharSetPredicate !CharacterCategory !Int
  -- ^ 'CharSetPredicate' does not return 'True' for a 'CharacterCategory' that
  -- requires at least 'Int' characters in the password
  deriving (Eq, Ord, Show)


-- | Check if given 'Password' fullfills all the Policies,
-- return true if given password is valid
--
-- This function is equivalent to @null $ validatePassword policy password@
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
  -- There is no point in validating the password if either policy or predicate is invalid.
  --
  -- So we validate 'PasswordPolicy' and 'CharSetPredicate' first,
  -- if they're valid, then validate 'Password'
  firstNonEmpty
   [ mconcat
      [ validatePasswordPolicy passwordPolicy
      , validateCharSetPredicate passwordPolicy charSetPredicate
      ]
   , catMaybes
      [ isTooShort
      , isTooLong
      , isUsingValidCharacters
      , hasRequiredChar uppercaseChars Uppercase
      , hasRequiredChar lowercaseChars Lowercase
      , hasRequiredChar specialChars Special
      , hasRequiredChar digitChars Digit
      ]
   ]
  where
    -- Return first non-empty list
    firstNonEmpty :: [[a]] -> [a]
    firstNonEmpty [] = []
    firstNonEmpty (x:xs)
      | null x = firstNonEmpty xs
      | otherwise = x
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
    isUsingValidCharacters :: Maybe InvalidReason
    isUsingValidCharacters =
        let filteredText = T.filter (\c -> not $ (getCharSetPredicate charSetPredicate) c) password
        in if T.null filteredText
          then Nothing
          else Just $ InvalidCharacters filteredText
    hasRequiredChar :: Maybe Int -> CharacterCategory -> Maybe InvalidReason
    hasRequiredChar Nothing _ = Nothing
    hasRequiredChar (Just requiredCharNum) characterCategory =
      let predicate = categoryToPredicate characterCategory
          actualRequiredCharNum = T.length $ T.filter predicate password
       in if actualRequiredCharNum >= requiredCharNum
          then Nothing
          else Just $ NotEnoughReqChars characterCategory requiredCharNum actualRequiredCharNum

-- | Validate 'CharSetPredicate' that it returns 'True' on at least one of the characters
-- that is required
--
-- For instance, if 'PasswordPolicy' states that the password requires at least
-- one uppercase letter, then 'CharSetPredicate' should return True on at least
-- one uppercase letter.
validateCharSetPredicate :: PasswordPolicy -> CharSetPredicate -> [InvalidReason]
validateCharSetPredicate PasswordPolicy{..} (CharSetPredicate predicate) =
  let charSets = accumulateCharSet
        [ (uppercaseChars, Uppercase)
        , (lowercaseChars, Lowercase)
        , (specialChars, Special)
        , (digitChars, Digit)
        ]
  in catMaybes $ map checkPredicate charSets
  where
    checkPredicate :: (Int, CharacterCategory, String) -> Maybe InvalidReason
    checkPredicate (num, category, sets) =
      if any predicate sets
        then Nothing
        else Just $ InvalidCharSetPredicate category num
    accumulateCharSet :: [(Maybe Int, CharacterCategory)] -> [(Int, CharacterCategory, String)]
    accumulateCharSet = map (\(num, c) -> (num, c, categoryToString c))
      . filter ((> 0) . fst)
      . map (\(mnum, c) -> (fromMaybe 0 mnum, c))
    categoryToString :: CharacterCategory -> String
    categoryToString category = filter (categoryToPredicate category) defaultCharSet

-- | Check that given 'PasswordPolicy' is valid
--
-- This function is equivalent to @null . validatePasswordPolicy@
isValidPasswordPolicy :: PasswordPolicy -> Bool
isValidPasswordPolicy = null . validatePasswordPolicy

-- | Checks if given 'PasswordPolicy' is valid
--
-- >>> validatePasswordPolicy defaultPasswordPolicy
-- []
validatePasswordPolicy :: PasswordPolicy -> [InvalidReason]
validatePasswordPolicy PasswordPolicy{..} = catMaybes [validMaxLength, validLength]
  where
    validLength :: Maybe InvalidReason
    validLength =
      if minimumLength <= maximumLength
        then Nothing
        else Just $ InvalidLength minimumLength maximumLength
    validMaxLength :: Maybe InvalidReason
    validMaxLength = if maximumLength > 0
      then Nothing
      else Just $ MaxLengthBelowZero maximumLength

-- | Default character sets
defaultCharSet :: String
defaultCharSet = chr <$> [32 .. 126]
