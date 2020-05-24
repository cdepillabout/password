{-# LANGUAGE CPP        #-}
{-# LANGUAGE LambdaCase #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Validate where

import Control.Monad (replicateM)
import Data.Char (isDigit, isLower, isUpper)
import Data.Maybe (fromMaybe, catMaybes)
import Data.Password (mkPassword)
import Data.Password.Validate (CharacterCategory (..), InvalidReason (..),
                               PasswordPolicy (..), defaultCharSet,
                               isValidPasswordPolicy, validatePassword)
import Data.Text (Text)
import qualified Data.Text as T
import Test.QuickCheck.Instances.Text ()
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, Property, choose, elements,
                              oneof, shuffle, suchThat, testProperty,
                              withMaxSuccess, (===))
#if! MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif

-- | Set of tests used for testing validate module
testValidate :: TestTree
testValidate =
  testGroup
    "validate"
    [ testProperty
        "Generator will always generate valid passwordPolicy"
        (\policy -> isValidPasswordPolicy policy),
      testProperty "Valid password always true" prop_ValidPassword,
      testProperty "Generator will always generate valid FailedReason"
        (\(InvalidPassword reason _ _) -> isValidReason reason),
      testProperty "validatePassword return appropriate value" prop_InvalidPassword
    ]

--------------------------------------------------------------------------------
-- Arbitrary instances
--------------------------------------------------------------------------------

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

instance Arbitrary CharacterCategory where
  arbitrary = elements [Uppercase, Lowercase, Special, Digit]

--------------------------------------------------------------------------------
-- Tests
--------------------------------------------------------------------------------

-- | Test that 'validatePassword' will always return empty list if the password
-- is valid
prop_ValidPassword :: ValidPassword -> Property
prop_ValidPassword (ValidPassword passwordPolicy password) =
  withMaxSuccess 1000 $ validatePassword passwordPolicy (mkPassword password) === []

-- | Data type used to generate valid password and 'PasswordPolicy' associated
-- with it
data ValidPassword = ValidPassword
  { validPasswordPolicy :: !PasswordPolicy
  , validPassText       :: !Text
  } deriving (Show)

instance Arbitrary ValidPassword where
  arbitrary = do
    policy <- arbitrary
    let minimumLength = passPolicyMinimumLength policy
    let maximumLength = passPolicyMaximumLength policy
    passLength <- choose (minimumLength, maximumLength)
    passwordText <- genPassword passLength policy
    return $ ValidPassword policy passwordText
    where
      genPassword :: Int -> PasswordPolicy -> Gen Text
      genPassword passLength policy = do
        upperCase <- genStr (passPolicyCharUppercase policy) upperCases
        lowerCase <- genStr (passPolicyCharLowercase policy) lowerCases
        specialChar <- genStr (passPolicyCharSpecial policy) specialChars
        digit <- genStr (passPolicyCharDigit policy) digits
        let requiredChars = upperCase <> lowerCase <> specialChar <> digit
        let toFill = passLength - (length requiredChars)
        fillChars <- replicateM toFill (elements $ T.unpack $ passPolicyCharSet policy)
        T.pack <$> shuffle (fillChars <> requiredChars)
      genStr :: Maybe Int -> String -> Gen String
      genStr mNum set = replicateM (fromMaybe 0 mNum) (elements set)

prop_InvalidPassword :: InvalidPassword -> Property
prop_InvalidPassword (InvalidPassword failedReason passwordPolicy password) =
  withMaxSuccess 1000 $ validatePassword passwordPolicy (mkPassword password) === [failedReason]

-- | Data type used to generate password which does not follow one of the policies
-- as well as 'InvalidReason' and 'PasswordPolicy' associated with it
data InvalidPassword = InvalidPassword
  { invalidPassFailedReason :: !InvalidReason
  , invalidPassPolicy       :: !PasswordPolicy
  , invalidPassText         :: !Text
  } deriving (Show)

instance Arbitrary InvalidPassword where
  arbitrary = do
    reason <- genFailedReason emptyPolicy
    let updatedPolicy = updatePolicy emptyPolicy reason
    passText <- genInvalidPassword updatedPolicy reason
    return $ InvalidPassword reason updatedPolicy (T.pack passText)
    where
      genFailedReason :: PasswordPolicy -> Gen InvalidReason
      genFailedReason policy =
        oneof
          [ genTooShort (passPolicyMaximumLength policy),
            genTooLong (passPolicyMinimumLength policy),
            genNotEnoughRequiredChars,
            genInvalidChar (T.unpack $ passPolicyCharSet policy),
            genInvalidPolicy
          ]
      genInvalidPolicy :: Gen InvalidReason
      genInvalidPolicy = return $ InvalidPasswordPolicy $ emptyPolicy { passPolicyMinimumLength = 0 }
      genTooShort :: Int -> Gen InvalidReason
      genTooShort maxLength = do
        requiredLength <- choose (1, maxLength - 1)
        actualLength <- choose (0, requiredLength - 1)
        return $ PasswordTooShort requiredLength actualLength
      genTooLong :: Int -> Gen InvalidReason
      genTooLong minLength = do
        requiredLength <- choose (minLength + 1, 30)
        actualLength <- choose (requiredLength + 1, 50)
        return $ PasswordTooLong requiredLength actualLength
      genNotEnoughRequiredChars :: Gen InvalidReason
      genNotEnoughRequiredChars = do
        required <- choose (1, 3)
        actual <- choose (0, required - 1)
        category <- arbitrary
        return $ NotEnoughReqChars category required actual
      genInvalidChar :: String -> Gen InvalidReason
      genInvalidChar charset = do
        num <- choose (1, 3)
        let arbitraryInvalidChar = arbitrary `suchThat` (\c -> c `notElem` charset)
        chrs <- replicateM num arbitraryInvalidChar
        return $ InvalidChar (T.pack chrs)
      updatePolicy :: PasswordPolicy -> InvalidReason -> PasswordPolicy
      updatePolicy policy = \case
        PasswordTooShort req _actual -> policy {passPolicyMinimumLength = req}
        PasswordTooLong req _actual -> policy {passPolicyMaximumLength = req}
        InvalidPasswordPolicy invalidPolicy -> invalidPolicy
        InvalidChar chrs ->
          let charset = T.filter (\c -> c `notElem` (T.unpack chrs)) $ passPolicyCharSet policy
          in policy { passPolicyCharSet = charset }
        NotEnoughReqChars category req _actual ->
          case category of
            Uppercase -> policy {passPolicyCharUppercase = Just req}
            Lowercase -> policy {passPolicyCharLowercase = Just req}
            Special   -> policy {passPolicyCharSpecial = Just req}
            Digit     -> policy {passPolicyCharDigit = Just req}
      genInvalidPassword :: PasswordPolicy -> InvalidReason -> Gen String
      genInvalidPassword policy = \case
        PasswordTooShort _req actual -> genPassword actual (passPolicyCharSet policy)
        PasswordTooLong _req actual -> genPassword actual (passPolicyCharSet policy)
        NotEnoughReqChars category _req actual -> do
          passwordLength <- genPasswordLength policy
          let predicate = case category of
                Uppercase -> isUpper
                Lowercase -> isLower
                Special   -> (\char -> char `elem` specialChars)
                Digit     -> isDigit
          let usableCharsets = T.filter (not . predicate) (passPolicyCharSet policy)
          let requiredCharsets = T.filter predicate (passPolicyCharSet policy)
          requiredChars <- replicateM actual (elements $ T.unpack $ requiredCharsets)
          passwordText <- genPassword (passwordLength - actual) usableCharsets
          shuffle (passwordText <> requiredChars)
        InvalidChar chrs -> do
          passwordLength <- genPasswordLength policy
          passwordText <- genPassword (passwordLength - T.length chrs) (passPolicyCharSet policy)
          -- Here, we make sure that the order of invalid characters are apporiate
          -- or else the test will fail. For instance this will make the test fail
          -- since the order of the characters are different
          -- e.g. [InvalidChar "一二三"] /= [InvalidChar "三二一"]
          shuffle (passwordText <> (T.unpack chrs)) `suchThat` (checkOrder policy (T.unpack chrs))
        InvalidPasswordPolicy _invalidPolicy -> do
          passwordLength <- genPasswordLength policy
          genPassword passwordLength (passPolicyCharSet policy)
      genPassword :: Int -> Text -> Gen String
      genPassword num set = replicateM num (elements $ T.unpack set)
      genPasswordLength :: PasswordPolicy -> Gen Int
      genPasswordLength policy = do
        let minLength = passPolicyMinimumLength policy
        let maxLength = passPolicyMaximumLength policy
        choose (minLength, maxLength)
      checkOrder :: PasswordPolicy -> String -> String -> Bool
      checkOrder policy invalidChars pass =
        let filteredChars = filter (\c -> c `notElem` (T.unpack $ passPolicyCharSet policy)) pass
         in invalidChars == filteredChars

-- | Check if given 'InvalidReason' is valid
isValidReason :: InvalidReason -> Bool
isValidReason = \case
  InvalidChar _ -> True
  InvalidPasswordPolicy policy -> not $ isValidPasswordPolicy policy
  PasswordTooLong required actual -> required < actual
  PasswordTooShort required actual -> required > actual
  NotEnoughReqChars _ required actual -> required > actual

-- | 'PasswordPolicy' used for testing
--
-- Required characters are turned off so that it's much more easier to test.
emptyPolicy :: PasswordPolicy
emptyPolicy = PasswordPolicy 8 32 Nothing Nothing Nothing Nothing defaultCharSet

upperCases :: String
upperCases = ['A' .. 'Z']

lowerCases :: String
lowerCases = ['a' .. 'z']

-- | Special characters
specialChars :: String
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"

digits :: String
digits = ['0' .. '9']
