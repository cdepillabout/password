{-# LANGUAGE CPP             #-}
{-# LANGUAGE LambdaCase      #-}
{-# LANGUAGE RecordWildCards #-}
{-# OPTIONS_GHC -Wno-orphans #-}

module Validate where

import Control.Monad (replicateM)
import Data.Char (chr, isAsciiLower, isAsciiUpper, isControl, isDigit)
import Data.Maybe (catMaybes, fromMaybe)
import Data.Password (mkPassword)
import Data.Password.Validate (CharSetPredicate (..), CharacterCategory (..),
                               InvalidReason (..), PasswordPolicy (..),
                               defaultCharSet, defaultCharSetPredicate,
                               isSpecial, isValidPasswordPolicy,
                               validatePassword)
import Data.Text (Text)
import qualified Data.Text as T
import Test.QuickCheck.Instances.Text ()
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck (Arbitrary (..), Gen, Property, choose, conjoin,
                              elements, liftArbitrary, oneof, shuffle, suchThat,
                              testProperty, withMaxSuccess, (===))
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
        (\policy -> isValidPasswordPolicy policy defaultCharSetPredicate),
      testProperty "Valid password always true" prop_ValidPassword,
      testProperty "Generator will always generate valid FailedReason"
        (\(InvalidPassword reason _ predicate _) -> isValidReason predicate reason),
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
    upperCase <- genMaybeInt
    lowerCase <- genMaybeInt
    special <- genMaybeInt
    digit <- genMaybeInt
    let sumLength = sum $ catMaybes [upperCase, lowerCase, special, digit]
    let minMaxLength = maximum [minLength, sumLength]
    maxLength <- choose (minMaxLength, minMaxLength + 10)
    return $ PasswordPolicy minLength maxLength upperCase lowerCase special digit
    where
      genMaybeInt :: Gen (Maybe Int)
      genMaybeInt = liftArbitrary (choose (1, 10))

instance Arbitrary CharacterCategory where
  arbitrary = elements [Uppercase, Lowercase, Special, Digit]

-- This is needed for testing (QuickCheck requires given datatype to have Show instance)
instance Show CharSetPredicate where
  show _ = "Character set predicate"

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
      genStr :: Maybe Int -> (Char -> Bool) -> Gen String
      genStr mNum predicate = replicateM (fromMaybe 0 mNum) (arbitrary `suchThat` predicate)

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
      genFailedReason PasswordPolicy{..} =
        oneof
          [ genTooShort maximumLength,
            genTooLong minimumLength,
            genNotEnoughRequiredChars,
            genInvalidChar defaultCharSetPredicate,
            genInvalidPolicy
          ]
      genInvalidPolicy :: Gen InvalidReason
      genInvalidPolicy = return $ InvalidPasswordPolicy $ emptyPolicy { minimumLength = 0 }
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
        return $ InvalidChar (T.pack chrs)
      -- Update 'PasswordPolicy' based upon 'InvalidReason'
      updatePolicy :: PasswordPolicy -> InvalidReason -> PasswordPolicy
      updatePolicy policy = \case
        PasswordTooShort req _actual -> policy {minimumLength = req}
        PasswordTooLong req _actual -> policy {maximumLength = req}
        InvalidPasswordPolicy invalidPolicy -> invalidPolicy
        InvalidChar _invalidChars -> policy
        NotEnoughReqChars category req _actual ->
          case category of
            Uppercase -> policy {uppercaseChars = Just req}
            Lowercase -> policy {lowercaseChars = Just req}
            Special   -> policy {specialChars = Just req}
            Digit     -> policy {digitChars = Just req}
      updateCharSetPredicate :: CharSetPredicate -> InvalidReason -> CharSetPredicate
      updateCharSetPredicate predicate = \case
        InvalidChar invalidChars ->
          CharSetPredicate $ \c -> (getCharSetPredicate predicate) c && c `notElem` (T.unpack invalidChars)
        _others -> predicate
      genInvalidPassword :: PasswordPolicy -> CharSetPredicate -> InvalidReason -> Gen String
      genInvalidPassword policy@PasswordPolicy{..} predicate = \case
        PasswordTooShort _req actual -> genPassword actual predicate
        PasswordTooLong _req actual -> genPassword actual predicate
        NotEnoughReqChars category _req actual -> do
          passwordLength <- genPasswordLength policy
          let pre = case category of
                Uppercase -> isAsciiUpper
                Lowercase -> isAsciiLower
                Special   -> isSpecial
                Digit     -> isDigit
          let usableCharsets = CharSetPredicate $ \c -> not (pre c) && (getCharSetPredicate predicate) c
          requiredChars <- replicateM actual (arbitrary `suchThat` pre)
          passwordText <- genPassword (passwordLength - actual) usableCharsets
          shuffle (passwordText <> requiredChars)
        InvalidChar chrs -> do
          passwordLength <- genPasswordLength policy
          passwordText <- genPassword (passwordLength - T.length chrs) predicate
          -- Here, we make sure that the order of invalid characters are apporiate
          -- or else the test will fail. For instance this will make the test fail
          -- since the order of the characters are different
          -- e.g. [InvalidChar "一二三"] /= [InvalidChar "三二一"]
          shuffle (passwordText <> (T.unpack chrs)) `suchThat` (checkOrder predicate (T.unpack chrs))
        InvalidPasswordPolicy _invalidPolicy -> do
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
isValidReason :: CharSetPredicate -> InvalidReason -> Bool
isValidReason predicate = \case
  InvalidChar _ -> True
  InvalidPasswordPolicy policy -> not $ isValidPasswordPolicy policy predicate
  PasswordTooLong required actual -> required < actual
  PasswordTooShort required actual -> required > actual
  NotEnoughReqChars _ required actual -> required > actual

-- | 'PasswordPolicy' used for testing
--
-- Required characters are turned off so that it's much more easier to test.
emptyPolicy :: PasswordPolicy
emptyPolicy = PasswordPolicy 8 32 Nothing Nothing Nothing Nothing
