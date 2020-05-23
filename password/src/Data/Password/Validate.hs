{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}

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
    -- * Default
    defaultPasswordPolicy,
    -- * Functions
    valid,
    validatePassword,
    -- * Utility
    isValidPasswordPolicy,
    defaultCharSet,
  ) where

import Data.Char (isDigit, isLower, isUpper)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Password.Internal (Password (..))
#if! MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, choose, elements, oneof)

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

-- | Set of policies used to validate 'Password'
data PasswordPolicy = PasswordPolicy
    { passPolicyMinimumLength :: !Int
    -- ^ Required password minimum length
    , passPolicyMaximumLength :: !Int
    -- ^ Required password maximum length
    , passPolicyCharUppercase :: !(Maybe Int)
    -- ^ Required number of upper-case characters
    , passPolicyCharLowercase :: !(Maybe Int)
    -- ^ Required number of lower-case characters
    , passPolicyCharSpecial   :: !(Maybe Int)
    -- ^ Required number of special characters
    , passPolicyCharDigit     :: !(Maybe Int)
    -- ^ Required number of ASCII-digit characters
    , passPolicyCharSet       :: !Text
    -- ^ Set of characters that can be used for password
    }
    deriving (Eq, Ord, Show)

-- | Generate valid PasswordPolicy
instance Arbitrary PasswordPolicy where
  arbitrary = do
    minimumLength <- choose (1, 10)
    upperCase <- genMaybeInt
    lowerCase <- genMaybeInt
    special <- genMaybeInt
    digit <- genMaybeInt
    let sumLength = sum $ catMaybes [upperCase, lowerCase, special, digit]
    let minMaxLength = maximum [minimumLength, sumLength]
    maximumLength <- choose (minMaxLength, minMaxLength + 10)
    return $ PasswordPolicy minimumLength maximumLength upperCase lowerCase special digit defaultCharSet
    where
      genMaybeInt :: Gen (Maybe Int)
      genMaybeInt = oneof [return Nothing, Just <$> (choose (1, 10))]

-- | Default value for the 'PasswordPolicy'
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { passPolicyMinimumLength = 8,
    passPolicyMaximumLength = 32,
    passPolicyCharUppercase = Just 1,
    passPolicyCharLowercase = Just 1,
    passPolicyCharSpecial = Nothing,
    passPolicyCharDigit = Just 1,
    passPolicyCharSet = defaultCharSet
  }

-- | Default character sets consist of uppercase, lowercase letters, numbers,
-- and special characters
defaultCharSet :: Text
defaultCharSet = T.pack $ specialChars <> ['A' .. 'Z'] <> ['a' .. 'z'] <> ['0' .. '9']

-- | Special characters
specialChars :: String
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"

-- | Character Category
data CharacterCategory
  = Uppercase
  | Lowercase
  | Special
  | Digit
  deriving (Eq, Ord, Show)

instance Arbitrary CharacterCategory where
  arbitrary = elements [Uppercase, Lowercase, Special, Digit]

-- | Data type representing how password are invalid
data InvalidReason
  = PasswordTooShort !Int !Int
  | PasswordTooLong !Int !Int
  | NotEnoughReqChars CharacterCategory !Int !Int
  | InvalidChar !Text
  | InvalidPasswordPolicy !PasswordPolicy
  deriving (Eq, Ord, Show)

-- | Check if given 'Password' fullfills all the Policies,
-- return true if given password is valid
--
-- This is equivalent to @null $ validatePassword policy password@
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> valid defaultPasswordPolicy pass
-- True
valid :: PasswordPolicy -> Password -> Bool
valid policy pass = null $ validatePassword policy pass

-- | Check if given 'Password' fulfills all of the Policies, returns list of
-- reasons why it's invalid.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy pass
-- []
validatePassword :: PasswordPolicy -> Password -> [InvalidReason]
validatePassword passwordPolicy (Password password) =
  catMaybes
    [ isValidLength,
      isTooShort,
      isTooLong,
      isUsingPolicyCharSet,
      hasRequiredChar (passPolicyCharUppercase passwordPolicy) Uppercase,
      hasRequiredChar (passPolicyCharLowercase passwordPolicy) Lowercase,
      hasRequiredChar (passPolicyCharSpecial passwordPolicy) Special,
      hasRequiredChar (passPolicyCharDigit passwordPolicy) Digit
    ]
  where
    isValidLength :: Maybe InvalidReason
    isValidLength =
      if isValidPasswordPolicy passwordPolicy
        then Nothing
        else Just $ InvalidPasswordPolicy passwordPolicy
    isTooLong :: Maybe InvalidReason
    isTooLong =
      let requiredMaxLength = passPolicyMaximumLength passwordPolicy
      in if T.length password <= requiredMaxLength
        then Nothing
        else Just $ PasswordTooLong requiredMaxLength (T.length password)
    isTooShort :: Maybe InvalidReason
    isTooShort =
      let requiredMinLength = passPolicyMinimumLength passwordPolicy
       in if T.length password >= requiredMinLength
          then Nothing
          else Just $ PasswordTooShort requiredMinLength (T.length password)
    isUsingPolicyCharSet :: Maybe InvalidReason
    isUsingPolicyCharSet =
        let filteredText = T.filter (\c -> c `notElem` (T.unpack $ passPolicyCharSet passwordPolicy)) password
        in if T.null filteredText
          then Nothing
          else Just $ InvalidChar filteredText
    hasRequiredChar :: Maybe Int -> CharacterCategory -> Maybe InvalidReason
    hasRequiredChar Nothing _ = Nothing
    hasRequiredChar (Just requiredCharNum) characterCategory =
      let predicate = case characterCategory of
            Uppercase -> isUpper
            Lowercase -> isLower
            Special   -> (\char -> char `elem` specialChars)
            Digit     -> isDigit
          actualRequiredCharNum = T.length $ T.filter predicate password
       in if actualRequiredCharNum >= requiredCharNum
          then Nothing
          else Just $ NotEnoughReqChars characterCategory requiredCharNum actualRequiredCharNum

-- | Checks if given 'PasswordPolicy' is valid
--
-- >>> isValidPasswordPolicy defaultPasswordPolicy
-- True
isValidPasswordPolicy :: PasswordPolicy -> Bool
isValidPasswordPolicy policy =
  let minimumLength = passPolicyMinimumLength policy
      maximumLength = passPolicyMaximumLength policy
  in and
   [ maximum [minimumLength, sumRequiredChars] <= maximumLength
   , minimumLength > 0
   , maximumLength > 0
   , isPositive (passPolicyCharUppercase policy)
   , isPositive (passPolicyCharLowercase policy)
   , isPositive (passPolicyCharSpecial policy)
   , isPositive (passPolicyCharDigit policy)
   , requiredCharsetValid
   ]
  where
    isPositive :: Maybe Int -> Bool
    isPositive mNum = maybe True (> 0) mNum
    sumRequiredChars :: Int
    sumRequiredChars =
      let uppercaseLength = fromMaybe 0 (passPolicyCharUppercase policy)
          lowercaseLength = fromMaybe 0 (passPolicyCharLowercase policy)
          specialLength = fromMaybe 0 (passPolicyCharSpecial policy)
          digitLength = fromMaybe 0 (passPolicyCharDigit policy)
      in uppercaseLength + lowercaseLength + specialLength + digitLength
    -- Check that character set fulfills the requirement
    -- (e.g. If policy states that it requires uppercase letters, check that
    -- the character set contain at least 1 uppercase letter)
    requiredCharsetValid :: Bool
    requiredCharsetValid =
      let charsets = passPolicyCharSet policy
          hasUpperCase = hasChar (passPolicyCharUppercase policy) Uppercase charsets
          hasLowerCase = hasChar (passPolicyCharLowercase policy) Lowercase charsets
          hasSpecial = hasChar (passPolicyCharSpecial policy) Special charsets
          hasDigits = hasChar (passPolicyCharDigit policy) Digit charsets
      in and [hasUpperCase, hasLowerCase, hasSpecial, hasDigits]
    hasChar :: Maybe Int -> CharacterCategory -> Text -> Bool
    hasChar Nothing _ _ = True
    hasChar (Just _) category sets =
      let predicate = case category of
            Uppercase -> isUpper
            Lowercase -> isLower
            Special   -> (\char -> char `elem` specialChars)
            Digit     -> isDigit
      in T.any predicate sets
