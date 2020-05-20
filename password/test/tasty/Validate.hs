module Validate
  ( testValidate,
  )
where

import Control.Monad (replicateM)
import Data.Password (mkPassword)
import Data.Password.Validate (PasswordPolicy (..), isValidPasswordPolicy, validatePassword)
import qualified Data.Text as T
import Data.Text (Text)
import Test.QuickCheck.Instances.Text ()
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck ((===), Arbitrary (..), Gen, Property, choose, elements, shuffle, testProperty)

testValidate :: TestTree
testValidate =
  testGroup
    "validate"
    [ testProperty "Will always generate valid passwordPolicy"
       (\policy -> isValidPasswordPolicy policy),
      testProperty "Valid password always true" prop_ValidPassword
    ]

prop_ValidPassword :: ValidPassword -> Property
prop_ValidPassword (ValidPassword passwordPolicy password) =
  validatePassword passwordPolicy (mkPassword password) === []

-- | Data type used to generate valid password
data ValidPassword
  = ValidPassword
      { validPasswordPolicy :: !PasswordPolicy,
        validPassText :: !Text
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
      genStr Nothing _ = return ""
      genStr (Just num) set = replicateM num (elements set)

upperCases :: String
upperCases = ['A' .. 'Z']

lowerCases :: String
lowerCases = ['a' .. 'z']

-- | Special characters
specialChars :: String
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"

digits :: String
digits = ['0' .. '9']
