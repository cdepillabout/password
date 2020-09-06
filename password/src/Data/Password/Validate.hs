{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

{-|
Module      : Data.Password.Valid
Copyright   : (c) Hiroto Shioi, 2020
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
  ( -- * Data types
    PasswordPolicy (..),
    InvalidReason (..),
    InvalidPolicyReason(..),
    CharacterCategory(..),
    ValidationResult(..),
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
    validatePasswordPolicy,
    isSpecial,
    defaultCharSet,
    categoryToPredicate,
    validateCharSetPredicate
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, isDigit, ord)
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
--
-- When defining your own 'PasswordPolicy', please keep in mind that:
--
-- * The value of 'maximumLength' must be bigger than 0
-- * The value of 'maximumLength' must be bigger than 'minimumLength'
-- * If any other field has negative value (e.g 'lowercaseChars'), it will be defaulted to 0
--
-- or else the validation functions will return one or more 'InvalidPolicyReason's.
--
-- If you're unsure of what to do, please use the default value 'defaultPasswordPolicy'
--
-- @since 2.1.0.0
data PasswordPolicy = PasswordPolicy
    { minimumLength  :: !Int
    -- ^ Required password minimum length
    , maximumLength  :: !Int
    -- ^ Required password maximum length
    , uppercaseChars :: !Int
    -- ^ Required number of upper-case characters
    , lowercaseChars :: !Int
    -- ^ Required number of lower-case characters
    , specialChars   :: !Int
    -- ^ Required number of special characters
    , digitChars     :: !Int
    -- ^ Required number of ASCII-digit characters
    } deriving (Eq, Ord, Show)

-- | Default value for the 'PasswordPolicy'
--
-- >>> defaultPasswordPolicy
-- PasswordPolicy {minimumLength = 8, maximumLength = 64, uppercaseChars = 1, lowercaseChars = 1, specialChars = 0, digitChars = 1}
--
-- @since 2.1.0.0
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { minimumLength = 8,
    maximumLength = 64,
    uppercaseChars = 1,
    lowercaseChars = 1,
    specialChars = 0,
    digitChars = 1
  }

-- | Predicate which defines the characters that can be used for a password.
--
-- @since 2.1.0.0
newtype CharSetPredicate = CharSetPredicate
  { getCharSetPredicate :: Char -> Bool
  }


-- | Default character sets consist of uppercase and lowercase letters, numbers,
-- and special characters from the ASCII character set.
--
-- @since 2.1.0.0
defaultCharSetPredicate :: CharSetPredicate
defaultCharSetPredicate =  CharSetPredicate $ \c -> ord c >= 32 && ord c <= 126
{-# INLINE defaultCharSetPredicate #-}

-- | Check if given 'Char' is a special character.
--
-- @since 2.1.0.0
isSpecial :: Char -> Bool
isSpecial = \c ->
    isDefault c && not (or [isAsciiUpper c, isAsciiLower c, isDigit c])
  where
    CharSetPredicate isDefault = defaultCharSetPredicate

-- | Character Category
--
-- @since 2.1.0.0
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

-- | Convert a 'CharacterCategory' into its associated predicate function
--
-- @since 2.1.0.0
categoryToPredicate :: CharacterCategory -> (Char -> Bool)
categoryToPredicate = \case
  Uppercase -> isAsciiUpper
  Lowercase -> isAsciiLower
  Special -> isSpecial
  Digit -> isDigit

-- | Possible reason for a 'Password' to be invalid.
--
-- @since 2.1.0.0
data InvalidReason
  = PasswordTooShort !Int !Int
  -- ^ Length of 'Password' is too short.
  --
  -- @PasswordTooShort expected found@
  | PasswordTooLong !Int !Int
  -- ^ Length of 'Password' is too long.
  --
  -- @PasswordTooLong expected found@
  | NotEnoughReqChars !CharacterCategory !Int !Int
  -- ^ 'Password' does not contain required number of characters.
  --
  -- @NotEnoughReqChars category expected found@
  | InvalidCharacters !Text
  -- ^ 'Password' contains characters that cannot be used
  deriving (Eq, Ord, Show)

-- | Possible reason of 'PasswordPolicy' being invalid
--
-- @since 2.1.0.0
data InvalidPolicyReason
  = InvalidLength !Int !Int
  -- ^ Value of 'minimumLength' is bigger than 'maximumLength'
  --
  -- @InvalidLength min max@
  | MaxLengthBelowZero !Int
  -- ^ Value of 'maximumLength' is zero or less
  | InvalidCharSetPredicate !CharacterCategory !Int
  -- ^ 'CharSetPredicate' does not return 'True' for a 'CharacterCategory' that
  -- requires at least 'Int' characters in the password
  deriving (Eq, Ord, Show)

-- | Result of validating a 'Password'.
--
-- Note that if the 'PasswordPolicy' is invalid, this will never return 'ValidPassword'.
--
-- @since 2.1.0.0
data ValidationResult
  = ValidPassword
  -- ^ The 'Password' conforms to the validation parameters
  | InvalidPassword [InvalidReason]
  -- ^ 'Password' failed to be validated for the given reasons
  | InvalidPolicy [InvalidPolicyReason]
  -- ^ 'PasswordPolicy' is invalid
  deriving (Eq, Show)

-- | Checks if the given 'Password' adheres to the given 'PasswordPolicy'
-- and 'CharSetPredicate', and returns @True@ if given a valid password.
--
-- This function is equivalent to @validatePassword policy charSetPredicate password == ValidPassword@
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> isValidPassword defaultPasswordPolicy defaultCharSetPredicate pass
-- True
--
-- @since 2.1.0.0
isValidPassword :: PasswordPolicy -> CharSetPredicate -> Password -> Bool
isValidPassword policy pre pass = validatePassword policy pre pass == ValidPassword
{-# INLINE isValidPassword #-}

-- | Check if given 'Password' fulfills all of the Policies, returns list of
-- reasons why it's invalid.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy defaultCharSetPredicate　pass
-- ValidPassword
--
-- @since 2.1.0.0
validatePassword :: PasswordPolicy -> CharSetPredicate -> Password -> ValidationResult
validatePassword policy@PasswordPolicy{..} charSetPredicate (Password password) = do
  -- There is no point in validating the password if either policy or predicate is invalid.
  --
  -- So we validate 'PasswordPolicy' and 'CharSetPredicate' first,
  -- if they're valid, then validate 'Password'
  let policyFailures = mconcat
        [ validatePasswordPolicy policy
        , validateCharSetPredicate policy charSetPredicate
        ]
      validationFailures = mconcat
        [ isTooShort
        , isTooLong
        , isUsingValidCharacters
        , hasRequiredChar uppercaseChars Uppercase
        , hasRequiredChar lowercaseChars Lowercase
        , hasRequiredChar specialChars Special
        , hasRequiredChar digitChars Digit
        ]
  case (policyFailures, validationFailures) of
    (_:_, _) -> InvalidPolicy policyFailures
    ([], []) -> ValidPassword
    ([], _)  -> InvalidPassword validationFailures

  where
    len = T.length password
    isTooLong = [PasswordTooLong maximumLength len | len > maximumLength]
    isTooShort = [PasswordTooShort minimumLength len | len < minimumLength]

    CharSetPredicate predicate = charSetPredicate
    isUsingValidCharacters :: [InvalidReason]
    isUsingValidCharacters =
        let filteredText = T.filter (not . predicate) password
        in [InvalidCharacters filteredText | not $ T.null filteredText]
    hasRequiredChar :: Int -> CharacterCategory -> [InvalidReason]
    hasRequiredChar requiredCharNum characterCategory
      | requiredCharNum <= 0 = []
      | otherwise =
          let p = categoryToPredicate characterCategory
              actualRequiredCharNum = T.length $ T.filter p password
          in [ NotEnoughReqChars characterCategory requiredCharNum actualRequiredCharNum
             | actualRequiredCharNum < requiredCharNum
             ]

-- | Validate 'CharSetPredicate' to return 'True' on at least one of the characters
-- that is required.
--
-- For instance, if 'PasswordPolicy' states that the password requires at least
-- one uppercase letter, then 'CharSetPredicate' should return True on at least
-- one uppercase letter.
--
-- @since 2.1.0.0
validateCharSetPredicate :: PasswordPolicy -> CharSetPredicate -> [InvalidPolicyReason]
validateCharSetPredicate PasswordPolicy{..} (CharSetPredicate predicate) =
  let charSets = accumulateCharSet
        [ (uppercaseChars, Uppercase)
        , (lowercaseChars, Lowercase)
        , (specialChars, Special)
        , (digitChars, Digit)
        ]
  in concatMap checkPredicate charSets
  where
    checkPredicate :: (Int, CharacterCategory, String) -> [InvalidPolicyReason]
    checkPredicate (num, category, sets) =
      [InvalidCharSetPredicate category num | not $ any predicate sets]
    accumulateCharSet :: [(Int, CharacterCategory)] -> [(Int, CharacterCategory, String)]
    accumulateCharSet xs =
      [ (num, c, categoryToString c)
      | (num, c) <- xs
      , num > 0
      ]
    categoryToString :: CharacterCategory -> String
    categoryToString category = filter (categoryToPredicate category) defaultCharSet

-- | Check that given 'PasswordPolicy' is valid
--
-- This function is equivalent to @null . validatePasswordPolicy@
--
-- @since 2.1.0.0
isValidPasswordPolicy :: PasswordPolicy -> Bool
isValidPasswordPolicy = null . validatePasswordPolicy
{-# INLINE isValidPasswordPolicy #-}

-- | Checks if given 'PasswordPolicy' is valid
--
-- >>> validatePasswordPolicy defaultPasswordPolicy
-- []
--
-- @since 2.1.0.0
validatePasswordPolicy :: PasswordPolicy -> [InvalidPolicyReason]
validatePasswordPolicy PasswordPolicy{..} = mconcat [validMaxLength, validLength]
  where
    validLength :: [InvalidPolicyReason]
    validLength =
      [InvalidLength minimumLength maximumLength | minimumLength > maximumLength]
    validMaxLength :: [InvalidPolicyReason]
    validMaxLength =
      [MaxLengthBelowZero maximumLength | maximumLength <= 0]

-- | Default character set
--
-- Should be all non-control characters in the ASCII character set.
--
-- @since 2.1.0.0
defaultCharSet :: String
defaultCharSet = chr <$> [32 .. 126]
