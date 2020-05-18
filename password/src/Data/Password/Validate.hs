{-# LANGUAGE LambdaCase #-}

{-|
Module      : Data.Password.Valid
Copyright   : (c) Dennis Gosnell, 2019; Felix Paulusma, 2020
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
  ( PasswordPolicy (..),
    PolicyCharSet(..),
    FailedPolicies (..),
    CharacterCategory(..),
    defaultPasswordPolicy,
    valid,
    validatePassword,
    specialChars,
  ) where

import Data.Char (isAscii, isDigit, isLower, isUpper)
import Data.Maybe (catMaybes)
import Data.Password.Internal (Password (..))
import qualified Data.Text as T

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

-- | Charset
data PolicyCharSet = PolicyCharSetAscii
  deriving (Eq, Ord, Show)

-- | Set of policies used to validate 'Password'
data PasswordPolicy
  = PasswordPolicy
      { passPolicyMinimumLength :: !Int,
        -- ^ Required password minimum length
        passPolicyMaximumLength :: !Int,
        -- ^ Required password maximum length
        passPolicyCharUppercase :: !(Maybe Int),
        -- ^ Required number of upper-case characters
        passPolicyCharLowercase :: !(Maybe Int),
        -- ^ Required number of lower-case characters
        passPolicyCharSpecial :: !(Maybe Int),
        -- ^ Required number of special characters
        passPolicyCharDigit :: !(Maybe Int),
        -- ^ Required number of ASCII-digit characters
        passPolicyCharSet :: PolicyCharSet
        -- ^ Set of characters that can be used for password
      } deriving (Eq, Ord, Show)

-- | Default value for the 'PasswordPolicy'
--
-- >>> defaultPasswordPolicy
-- PasswordPolicy {passPolicyMinimumLength = 8, passPolicyMaximumLength = 30, passPolicyCharUppercase = Just 1, passPolicyCharLowercase = Just 1, passPolicyCharSpecial = Nothing, passPolicyCharDigit = Just 1, passPolicyCharSet = PolicyCharSetAscii}
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { passPolicyMinimumLength = 8,
    passPolicyMaximumLength = 30,
    passPolicyCharUppercase = Just 1,
    passPolicyCharLowercase = Just 1,
    passPolicyCharSpecial = Nothing,
    passPolicyCharDigit = Just 1,
    passPolicyCharSet = PolicyCharSetAscii
  }

-- | Character Category
data CharacterCategory
  = Uppercase
  | Lowercase
  | Special
  | Digit
  deriving (Eq, Ord, Show)

-- | Data type representing how password are invalid
data FailedPolicies
  = PasswordTooShort Int Int
  -- ^ Password is too short
  | PasswordTooLong Int Int
  -- ^ Password is too long
  | NotEnoughReqChars CharacterCategory Int Int
  -- ^ Password does not contain characters that are required
  | InvalidChar PolicyCharSet
  -- ^ Password contains invalid character sets
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
-- policies that failed.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy pass
-- []
validatePassword :: PasswordPolicy -> Password -> [FailedPolicies]
validatePassword passwordPolicy (Password password) =
  catMaybes
    [ isTooShort,
      isTooLong,
      isUsingPolicyCharSet,
      hasRequiredChar (passPolicyCharUppercase passwordPolicy) Uppercase,
      hasRequiredChar (passPolicyCharLowercase passwordPolicy) Lowercase,
      hasRequiredChar (passPolicyCharSpecial passwordPolicy) Special,
      hasRequiredChar (passPolicyCharDigit passwordPolicy) Digit
    ]
  where
    isTooLong :: Maybe FailedPolicies
    isTooLong =
      let policyLength = passPolicyMaximumLength passwordPolicy
      in if T.length password <= policyLength
        then Nothing
        else Just $ PasswordTooLong policyLength (T.length password)
    isTooShort :: Maybe FailedPolicies
    isTooShort =
      let policyLength = passPolicyMinimumLength passwordPolicy
       in if T.length password >= policyLength
            then Nothing
            else Just $ PasswordTooShort policyLength (T.length password)
    isUsingPolicyCharSet :: Maybe FailedPolicies
    isUsingPolicyCharSet = case (passPolicyCharSet passwordPolicy) of
      PolicyCharSetAscii ->
        if T.all isAscii password
          then Nothing
          else Just $ InvalidChar PolicyCharSetAscii
    hasRequiredChar :: Maybe Int -> CharacterCategory -> Maybe FailedPolicies
    hasRequiredChar Nothing _ = Nothing
    hasRequiredChar (Just requiredCharNum) characterCategory =
      let predicate = case characterCategory of
            Uppercase -> isUpper
            Lowercase -> isLower
            Special -> (\char -> char `elem` specialChars)
            Digit -> isDigit
          passwordCharNum = T.length $ T.filter predicate password
       in if passwordCharNum >= requiredCharNum
            then Nothing
            else Just $ NotEnoughReqChars characterCategory requiredCharNum passwordCharNum

-- | Special characters
specialChars :: [Char]
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"
