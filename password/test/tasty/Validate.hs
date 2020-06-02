{-# LANGUAGE CPP             #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Validate where

import Control.Monad (replicateM)
import Data.Char (chr, isAsciiLower, isAsciiUpper, isControl, isDigit)
import Data.Password (mkPassword)
import Data.Password.Validate (CharSetPredicate (..), CharacterCategory (..),
                               InvalidReason (..), PasswordPolicy (..),
                               categoryToPredicate, defaultCharSet,
                               defaultCharSetPredicate, isSpecial,
                               isValidPasswordPolicy, validatePassword)
import Data.Text (Text)
import qualified Data.Text as T
import Test.QuickCheck.Instances.Text ()
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, Property, choose, conjoin,
                              elements, oneof, shuffle, suchThat, testProperty,
                              withMaxSuccess, (===))
#if! MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif

-- | Set of tests used for testing validate module
testValidate :: TestTree
testValidate =
  testGroup
    "validate"
    [ testGroup "defaultCharSetPredicate"
        [ testProperty "Return false on all control characters"
            (not $ all (getCharSetPredicate defaultCharSetPredicate) asciiControlChars),
          testProperty "Return true on all non-control characters"
            (all (getCharSetPredicate defaultCharSetPredicate) asciiNonControlChars)
        ]
      ,
      testProperty "defaultCharSet should contain all the expected characters" $
        (conjoin
          [ hasCharacters isAsciiUpper 26
          , hasCharacters isAsciiLower 26
          , hasCharacters isDigit 10
          , hasCharacters isSpecial 33
          ]
        ),
      testProperty
        "Generator will always generate valid passwordPolicy"
        (\policy -> isValidPasswordPolicy policy),
      testProperty "Valid password always true" prop_ValidPassword,
      testProperty "Generator will always generate valid FailedReason"
        (\(InvalidPassword reason _ _ _) -> isValidReason reason),
      testProperty "validatePassword return appropriate value" prop_InvalidPassword
    ]
  where
    -- Check that the number of characters filtered from defaultCharSet is as expected
    hasCharacters :: (Char -> Bool) -> Int -> Property
    hasCharacters pre expected = length (filter pre defaultCharSet) === expected
    asciiCharSet :: [Char]
    asciiCharSet = chr <$> [0 .. 127]
    asciiControlChars :: [Char]
    asciiControlChars = filter isControl asciiCharSet
    asciiNonControlChars :: [Char]
    asciiNonControlChars = filter (not . isControl) asciiCharSet

--------------------------------------------------------------------------------
-- Typeclass instances
--------------------------------------------------------------------------------

-- | Generate valid PasswordPolicy
instance Arbitrary PasswordPolicy where
  arbitrary = do
    minLength <- choose (1, 10)
    upperCase <- genCharLength
    lowerCase <- genCharLength
    special <- genCharLength
    digit <- genCharLength
    let sumLength = sum [upperCase, lowerCase, special, digit]
    let minMaxLength = max minLength sumLength
    maxLength <- choose (minMaxLength, minMaxLength + 10)
    return $ PasswordPolicy minLength maxLength upperCase lowerCase special digit
    where
      genCharLength :: Gen Int
      genCharLength = (choose (1, 10))

instance Arbitrary CharacterCategory where
  arbitrary = elements [Uppercase, Lowercase, Special, Digit]

-- This is needed for testing (QuickCheck requires given datatype to have Show instance)
instance Show CharSetPredicate where
  show _ = "Predicate"

--------------------------------------------------------------------------------
-- Tests
--------------------------------------------------------------------------------

-- | Test that 'validatePassword' will always return empty list if the password
-- is valid
prop_ValidPassword :: ValidPassword -> Property
prop_ValidPassword (ValidPassword passwordPolicy predicate password) =
  withMaxSuccess 1000 $ validatePassword passwordPolicy predicate (mkPassword password) === []

-- | Data type used to generate valid password and 'PasswordPolicy' associated
-- with it
data ValidPassword = ValidPassword
  { validPasswordPolicy   :: !PasswordPolicy
  , validCharSetPredicate :: !CharSetPredicate
  , validPassText         :: !Text
  } deriving (Show)

instance Arbitrary ValidPassword where
  arbitrary = do
    policy@PasswordPolicy{..} <- arbitrary
    passLength <- choose (minimumLength, maximumLength)
    passwordText <- genPassword passLength policy defaultCharSetPredicate
    return $ ValidPassword policy defaultCharSetPredicate passwordText
    where
      genPassword :: Int -> PasswordPolicy -> CharSetPredicate -> Gen Text
      genPassword passLength PasswordPolicy{..} predicate = do
        upperCase <- genStr uppercaseChars isAsciiUpper
        lowerCase <- genStr lowercaseChars isAsciiLower
        specialChar <- genStr specialChars isSpecial
        digit <- genStr digitChars isDigit
        let requiredChars = upperCase <> lowerCase <> specialChar <> digit
        let toFill = passLength - (length requiredChars)
        fillChars <- replicateM toFill (arbitrary `suchThat` (\c -> (getCharSetPredicate predicate) c))
        T.pack <$> shuffle (fillChars <> requiredChars)
      genStr :: Int -> (Char -> Bool) -> Gen String
      genStr num predicate = replicateM num (arbitrary `suchThat` predicate)

prop_InvalidPassword :: InvalidPassword -> Property
prop_InvalidPassword (InvalidPassword failedReason passwordPolicy charSetPredicate password) =
  withMaxSuccess 1000 $ validatePassword passwordPolicy charSetPredicate (mkPassword password) === [failedReason]

-- | Data type used to generate password which does not follow one of the policies
-- as well as 'InvalidReason', 'CharSetPredicate', and 'PasswordPolicy' associated with it
data InvalidPassword = InvalidPassword
  { invalidPassFailedReason :: !InvalidReason
  , invalidPassPolicy       :: !PasswordPolicy
  , invalidCharSetPredicate :: !CharSetPredicate
  , invalidPassText         :: !Text
  } deriving (Show)

instance Arbitrary InvalidPassword where
  arbitrary = do
    reason <- genFailedReason emptyPolicy
    let updatedPolicy = updatePolicy emptyPolicy reason
    let charSetPredicate = updateCharSetPredicate defaultCharSetPredicate reason
    passText <- genInvalidPassword updatedPolicy charSetPredicate reason
    return $ InvalidPassword reason updatedPolicy charSetPredicate (T.pack passText)
    where
      genFailedReason :: PasswordPolicy -> Gen InvalidReason
      genFailedReason policy@PasswordPolicy{..} =
        oneof
          [ genTooShort maximumLength,
            genTooLong minimumLength,
            genNotEnoughRequiredChars,
            genInvalidChar defaultCharSetPredicate,
            MaxLengthBelowZero <$> (arbitrary `suchThat` (<= 0)),
            genInvalidLength policy,
            InvalidCharSetPredicate <$> arbitrary <*> choose (minimumLength, maximumLength)
          ]
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
      genInvalidChar :: CharSetPredicate -> Gen InvalidReason
      genInvalidChar (CharSetPredicate predicate) = do
        num <- choose (1, 3)
        let arbitraryInvalidChar = arbitrary `suchThat` (not . predicate)
        chrs <- replicateM num arbitraryInvalidChar
        return $ InvalidCharacters (T.pack chrs)
      genInvalidLength :: PasswordPolicy -> Gen InvalidReason
      genInvalidLength PasswordPolicy{..} = do
        let sumReq = sum [uppercaseChars, lowercaseChars, specialChars, digitChars]
        minLength <- choose (sumReq, maximumLength - 1) `suchThat` (> 0)
        return $ InvalidLength maximumLength minLength
      -- Update 'PasswordPolicy' based upon 'InvalidReason'
      updatePolicy :: PasswordPolicy -> InvalidReason -> PasswordPolicy
      updatePolicy policy = \case
        PasswordTooShort req _actual -> policy {minimumLength = req}
        PasswordTooLong req _actual -> policy {maximumLength = req}
        InvalidCharacters _invalidChars -> policy
        NotEnoughReqChars category req _actual ->
          case category of
            Uppercase -> policy {uppercaseChars = req}
            Lowercase -> policy {lowercaseChars = req}
            Special   -> policy {specialChars = req}
            Digit     -> policy {digitChars = req}
        MaxLengthBelowZero num ->
          policy
            { minimumLength = num - 1
            , maximumLength = num
            }
        InvalidLength minLength maxLength ->
          policy
            { minimumLength = minLength
            , maximumLength = maxLength
            }
        InvalidCharSetPredicate category num ->
          case category of
            Uppercase -> policy {uppercaseChars = num}
            Lowercase -> policy {lowercaseChars = num}
            Special   -> policy {specialChars = num}
            Digit     -> policy {digitChars = num}
      updateCharSetPredicate :: CharSetPredicate -> InvalidReason -> CharSetPredicate
      updateCharSetPredicate predicate = \case
        InvalidCharacters invalidChars ->
          CharSetPredicate $ \c -> (getCharSetPredicate predicate) c && c `notElem` (T.unpack invalidChars)
        InvalidCharSetPredicate category _num ->
          let filterPre = categoryToPredicate category
          in CharSetPredicate $ \c -> and [(getCharSetPredicate predicate) c, (not . filterPre) c]
        _others -> predicate
      genInvalidPassword :: PasswordPolicy -> CharSetPredicate -> InvalidReason -> Gen String
      genInvalidPassword policy@PasswordPolicy{..} predicate = \case
        PasswordTooShort _req actual -> genPassword actual predicate
        PasswordTooLong _req actual -> genPassword actual predicate
        NotEnoughReqChars category _req actual -> do
          passwordLength <- genPasswordLength policy
          let pre = categoryToPredicate category
          let usableCharsets = CharSetPredicate $ \c -> not (pre c) && (getCharSetPredicate predicate) c
          requiredChars <- replicateM actual (arbitrary `suchThat` pre)
          passwordText <- genPassword (passwordLength - actual) usableCharsets
          shuffle (passwordText <> requiredChars)
        InvalidCharacters chrs -> do
          passwordLength <- genPasswordLength policy
          passwordText <- genPassword (passwordLength - T.length chrs) predicate
          -- Here, we make sure that the order of invalid characters are apporiate
          -- or else the test will fail. For instance this will make the test fail
          -- since the order of the characters are different
          -- e.g. [InvalidChar "一二三"] /= [InvalidChar "三二一"]
          shuffle (passwordText <> (T.unpack chrs)) `suchThat` (checkOrder predicate (T.unpack chrs))
        MaxLengthBelowZero _invalid -> genPassword (minimumLength) predicate
        _others -> do
          passwordLength <- genPasswordLength policy
          genPassword passwordLength predicate
      genPassword :: Int -> CharSetPredicate -> Gen String
      genPassword num (CharSetPredicate predicate) = replicateM num (arbitrary `suchThat` predicate)
      genPasswordLength :: PasswordPolicy -> Gen Int
      genPasswordLength PasswordPolicy{..} = choose (minimumLength, maximumLength)
      checkOrder :: CharSetPredicate -> String -> String -> Bool
      checkOrder (CharSetPredicate predicate) invalidChars password =
        let filteredChars = filter (\c -> (not . predicate) c) password
         in invalidChars == filteredChars

-- | Check if given 'InvalidReason' is valid
isValidReason :: InvalidReason -> Bool
isValidReason = \case
  InvalidCharacters _ -> True
  PasswordTooLong required actual -> required < actual
  PasswordTooShort required actual -> required > actual
  NotEnoughReqChars _ required actual -> required > actual
  InvalidLength minLength maxLength -> minLength > maxLength
  MaxLengthBelowZero num -> num <= 0
  InvalidCharSetPredicate _category num -> num > 0

-- | 'PasswordPolicy' used for testing
--
-- Required characters are turned off so that it's much more easier to test.
emptyPolicy :: PasswordPolicy
emptyPolicy = PasswordPolicy 8 32 0 0 0 0
