{-# LANGUAGE LambdaCase #-}

module Data.Password.Validate
  ( PasswordPolicy (..),
    PolicyCharSet,
    FailedPolicies (..),
    defaultPasswordPolicy,
    validatePassword',
    validatePassword,
    specialChars,
  ) where

import Data.Char (isAscii, isDigit, isLower, isUpper)
import Data.Maybe (catMaybes)
import Data.Password.Internal (Password (..))
import qualified Data.Text as T

-- TODO: Create code for checking that plain-text passwords conform to some sort of
-- password policy.

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

data PolicyCharSet = PolicyCharSetAscii
  deriving (Eq, Ord, Show)

data PasswordPolicy
  = PasswordPolicy
      { -- | Required password length
        passPolicyLength :: !Int,
        -- | Required number of upper-case characters
        passPolicyCharUpper :: !(Maybe Int),
        -- | Required number of lower-case characters
        passPolicyCharLower :: !(Maybe Int),
        -- | Required number of special characters
        passPolicyCharSpecial :: !(Maybe Int),
        -- | Required number of ASCII-digit characters
        passPolicyCharDigit :: !(Maybe Int),
        -- | Set of characters that can be used for password
        passPolicyCharSet :: PolicyCharSet
      }
  deriving (Eq, Ord, Show)

-- | Default parameters for the 'PasswordPolicy'
--
-- >>> defaultPasswordPolicy
-- PasswordPolicy {passPolicyLength = 10, passPolicyCharUpper = Just 1, passPolicyCharLower = Just 1, passPolicyCharSpecial = Nothing, passPolicyCharDigit = Just 1, passPolicyCharSet = PolicyCharSetAscii}
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
  { passPolicyLength = 10,
    passPolicyCharUpper = Just 1,
    passPolicyCharLower = Just 1,
    passPolicyCharSpecial = Nothing,
    passPolicyCharDigit = Just 1,
    passPolicyCharSet = PolicyCharSetAscii
  }

data CharType
  = Upper
  | Lower
  | Special
  | Digit
  deriving (Eq, Ord, Show)

-- | Data type representing how password are invalid
data FailedPolicies
  = -- | Given password does not have enough length
    NotEnoughLength Int Int
  | -- | Given password does not fulfill one of the characther requirements
    NotEnoughReqChars CharType Int Int
  | -- | Invalid character was used
    InvalidChar PolicyCharSet
  deriving (Eq, Ord, Show)

-- | Check if given 'Password' fullfills all the Policies,
-- return true if given password is valid
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> validatePassword' defaultPasswordPolicy pass
-- True
validatePassword' :: PasswordPolicy -> Password -> Bool
validatePassword' policy password = null $ validatePassword policy password

-- | Check if given 'Password' fills all the Policies, returns list of
-- policies that failed.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy pass
-- []
validatePassword :: PasswordPolicy -> Password -> [FailedPolicies]
validatePassword passwordPolicy (Password password) =
  catMaybes
    [ hasEnoughLength,
      isUsingPolicyCharSet,
      hasRequiredChar (passPolicyCharUpper passwordPolicy) Upper,
      hasRequiredChar (passPolicyCharLower passwordPolicy) Lower,
      hasRequiredChar (passPolicyCharSpecial passwordPolicy) Special,
      hasRequiredChar (passPolicyCharDigit passwordPolicy) Digit
    ]
  where
    hasEnoughLength :: Maybe FailedPolicies
    hasEnoughLength =
      let policyLength = passPolicyLength passwordPolicy
       in if T.length password > policyLength
            then Nothing
            else Just $ NotEnoughLength (T.length password) policyLength
    isUsingPolicyCharSet :: Maybe FailedPolicies
    isUsingPolicyCharSet = case (passPolicyCharSet passwordPolicy) of
      PolicyCharSetAscii ->
        if T.all isAscii password
          then Nothing
          else Just $ InvalidChar PolicyCharSetAscii
    hasRequiredChar :: Maybe Int -> CharType -> Maybe FailedPolicies
    hasRequiredChar Nothing _ = Nothing
    hasRequiredChar (Just requiredCharNum) charType =
      let predicate = case charType of
            Upper -> isUpper
            Lower -> isLower
            Special -> (\char -> char `elem` specialChars)
            Digit -> isDigit
          passwordCharNum = T.length $ T.filter predicate password
       in if passwordCharNum > requiredCharNum
            then Nothing
            else Just $ NotEnoughReqChars charType passwordCharNum requiredCharNum

-- https://www.ipvoid.com/password-special-characters/
-- https://owasp.org/www-community/password-special-characters
specialChars :: [Char]
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"
