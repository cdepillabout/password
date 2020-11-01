{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}

{-|
Module      : Data.Password.Valid
Copyright   : (c) Hiroto Shioi, 2020; Felix Paulusma, 2020
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
  ( -- * Validating passwords
    validatePassword,
    isValidPassword,
    ValidationResult(..),
    -- ** Password Policy
    validatePasswordPolicy,
    PasswordPolicy (..),
    ValidPasswordPolicy,
    unValidatePasswordPolicy,
    defaultPasswordPolicy,
    defaultPasswordPolicy_,
    CharSetPredicate(..),
    defaultCharSetPredicate,
    InvalidReason (..),
    InvalidPolicyReason(..),
    CharacterCategory(..),
    ExpectedLength,
    ProvidedLength,
    ExpectedAmount,
    ProvidedAmount,
    -- * For internal use
    defaultCharSet,
    validateCharSetPredicate,
    categoryToPredicate,
    isSpecial
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, isDigit, ord)
import Data.Function (on)
#if! MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T

import Data.Password.Internal (Password (..))

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

{-
TODO: Add a QuasiQuoter to check password policies at compile time.
-}

-- | Set of policies used to validate a 'Password'.
--
-- When defining your own 'PasswordPolicy', please keep in mind that:
--
-- * The value of 'maximumLength' must be bigger than 0
-- * The value of 'maximumLength' must be bigger than 'minimumLength'
-- * If any other field has a negative value (e.g 'lowercaseChars'), it will be defaulted to 0
-- * The provided 'CharSetPredicate' needs to allow at least one of the characters in the
--   categories which require more than 0 characters. (e.g. if 'lowercaseChars' is > 0,
--   the 'charSetPredicate' must allow at least one of the characters in @['a'..'z']@)
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
    , charSetPredicate :: CharSetPredicate
    -- ^ Which characters are acceptable for use in passwords (cf. 'defaultCharSetPredicate')
    }

allButCSP :: PasswordPolicy -> [Int]
allButCSP PasswordPolicy{..} =
  [ minimumLength
  , maximumLength
  , uppercaseChars
  , lowercaseChars
  , specialChars
  , digitChars
  ]

-- | N.B. This will not check equality on the 'charSetPredicate'
instance Eq PasswordPolicy where
  (==) = go `on` allButCSP
    where
      go a b = and $ zipWith (==) a b

-- | N.B. This will not check order on the 'charSetPredicate'
instance Ord PasswordPolicy where
  compare = go `on` allButCSP
    where
      go a b = check $ zipWith compare a b
      check [] = EQ
      check (EQ : xs) = check xs
      check (x : _) = x

instance Show PasswordPolicy where
  show PasswordPolicy{..} = mconcat
    [ "PasswordPolicy {"
    , "minimumLength = ", show minimumLength
    , ", maximumLength = ", show maximumLength
    , ", uppercaseChars = ", show uppercaseChars
    , ", lowercaseChars = ", show lowercaseChars
    , ", specialChars = ", show specialChars
    , ", digitChars = ", show digitChars
    , ", charSetPredicate = <FUNCTION>}"
    ]

-- | A 'PasswordPolicy' that has been checked to be valid
--
-- @since 2.1.0.0
newtype ValidPasswordPolicy = VPP
  { unValidatePasswordPolicy :: PasswordPolicy
  } deriving (Eq, Show)

-- | Default value for the 'PasswordPolicy'.
--
-- Enforces that a password must be between 8-64 characters long and
-- have at least one uppercase letter, one lowercase letter and one digit.
--
-- This policy is guaranteed to be valid. Any changes made to it might result
-- in 'validatePassword' returning 'InvalidPolicy'. If you need to be sure it's
-- valid, use 'validatePasswordPolicy'.
--
-- >>> defaultPasswordPolicy
-- PasswordPolicy {minimumLength = 8, maximumLength = 64, uppercaseChars = 1, lowercaseChars = 1, specialChars = 0, digitChars = 1, charSetPredicate = <FUNCTION>}
--
-- @since 2.1.0.0
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { minimumLength = 8,
    maximumLength = 64,
    uppercaseChars = 1,
    lowercaseChars = 1,
    specialChars = 0,
    digitChars = 1,
    charSetPredicate = defaultCharSetPredicate
  }

-- | Unchangeable 'defaultPasswordPolicy', but guaranteed to be valid.
--
-- @since 2.1.0.0
defaultPasswordPolicy_ :: ValidPasswordPolicy
defaultPasswordPolicy_ = VPP defaultPasswordPolicy

-- | Predicate which defines the characters that can be used for a password.
--
-- @since 2.1.0.0
newtype CharSetPredicate = CharSetPredicate
  { getCharSetPredicate :: Char -> Bool
  }

-- | The default character set consists of uppercase and lowercase letters, numbers,
-- and special characters from the ASCII character set.
-- (i.e. everything from the ASCII set except the control characters)
--
-- @since 2.1.0.0
defaultCharSetPredicate :: CharSetPredicate
defaultCharSetPredicate =  CharSetPredicate $ \c -> ord c >= 32 && ord c <= 126
{-# INLINE defaultCharSetPredicate #-}

-- | Check if given 'Char' is a special character.
-- (i.e. any non-alphanumeric non-control ASCII character)
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

type ExpectedLength = Int
type ProvidedLength = Int
type ExpectedAmount = Int
type ProvidedAmount = Int

-- | Possible reasons for a 'Password' to be invalid.
--
-- @since 2.1.0.0
data InvalidReason
  = PasswordTooShort !ExpectedLength !ProvidedLength
  -- ^ Length of 'Password' is too short.
  | PasswordTooLong !ExpectedLength !ProvidedLength
  -- ^ Length of 'Password' is too long.
  | NotEnoughReqChars !CharacterCategory !ExpectedAmount !ProvidedAmount
  -- ^ 'Password' does not contain required number of characters.
  | InvalidCharacters !Text
  -- ^ 'Password' contains characters that cannot be used
  deriving (Eq, Ord, Show)

-- | Possible reasons for a 'PasswordPolicy' to be invalid
--
-- @since 2.1.0.0
data InvalidPolicyReason
  = InvalidLength !ProvidedLength !ProvidedLength
  -- ^ Value of 'minimumLength' is bigger than 'maximumLength'
  --
  -- @InvalidLength minLength maxLength@
  | MaxLengthBelowZero !ProvidedLength
  -- ^ Value of 'maximumLength' is zero or less
  --
  -- @MaxLengthBelowZero maxLength@
  | InvalidCharSetPredicate !CharacterCategory !ExpectedAmount
  -- ^ 'charSetPredicate' does not return 'True' for a 'CharacterCategory' that
  -- requires at least 'ExpectedAmount' characters in the password
  deriving (Eq, Ord, Show)

-- | Result of validating a 'Password'.
--
-- @since 2.1.0.0
data ValidationResult = ValidPassword | InvalidPassword [InvalidReason]
  deriving (Eq, Show)

-- | Checks if the given 'Password' adheres to the given 'PasswordPolicy'
-- and 'CharSetPredicate', and returns @True@ if given a valid password.
--
-- This function is equivalent to @'validatePassword' policy charSetPredicate password == 'ValidPassword'@
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> isValidPassword defaultPasswordPolicy defaultCharSetPredicate pass
-- True
--
-- @since 2.1.0.0
isValidPassword :: ValidPasswordPolicy -> Password -> Bool
isValidPassword policy pass = validatePassword policy pass == ValidPassword
{-# INLINE isValidPassword #-}

-- | Checks if a given 'Password' adheres to the provided 'PasswordPolicy'.
--
-- Note that if the 'PasswordPolicy' is invalid, this will never return 'ValidPassword'.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy pass
-- ValidPassword
--
-- @since 2.1.0.0
validatePassword :: ValidPasswordPolicy -> Password -> ValidationResult
validatePassword (VPP PasswordPolicy{..}) (Password password) =
  case validationFailures of
    [] -> ValidPassword
    _:_ -> InvalidPassword validationFailures

  where
    validationFailures = mconcat
        [ isTooShort
        , isTooLong
        , isUsingValidCharacters
        , hasRequiredChar uppercaseChars Uppercase
        , hasRequiredChar lowercaseChars Lowercase
        , hasRequiredChar specialChars Special
        , hasRequiredChar digitChars Digit
        ]
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
validateCharSetPredicate :: PasswordPolicy -> [InvalidPolicyReason]
validateCharSetPredicate PasswordPolicy{..} =
  let charSets = accumulateCharSet
        [ (uppercaseChars, Uppercase)
        , (lowercaseChars, Lowercase)
        , (specialChars, Special)
        , (digitChars, Digit)
        ]
  in concatMap checkPredicate charSets
  where
    CharSetPredicate predicate = charSetPredicate
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

-- | Verifies that a 'PasswordPolicy' is valid and converts it into a 'ValidPasswordPolicy'.
--
-- >>> validatePasswordPolicy defaultPasswordPolicy
-- Right (...)
--
-- @since 2.1.0.0
validatePasswordPolicy :: PasswordPolicy -> Either [InvalidPolicyReason] ValidPasswordPolicy
validatePasswordPolicy policy@PasswordPolicy{..} =
    case allReasons of
      [] -> Right $ VPP policy
      _ -> Left allReasons
  where
    allReasons = mconcat [validMaxLength, validLength, validPredicate]
    validLength, validMaxLength, validPredicate :: [InvalidPolicyReason]
    validLength =
      [InvalidLength minimumLength maximumLength | minimumLength > maximumLength]
    validMaxLength =
      [MaxLengthBelowZero maximumLength | maximumLength <= 0]
    validPredicate = validateCharSetPredicate policy

-- | Default character set
--
-- Should be all non-control characters in the ASCII character set.
--
-- @since 2.1.0.0
defaultCharSet :: String
defaultCharSet = chr <$> [32 .. 126]
