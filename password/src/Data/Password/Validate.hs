{-# LANGUAGE CPP               #-}
{-# LANGUAGE LambdaCase        #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards   #-}
{-# LANGUAGE TemplateHaskell   #-}

{-|
Module      : Data.Password.Validate
Copyright   : (c) Hiroto Shioi, 2020; Felix Paulusma, 2020
License     : BSD-style (see LICENSE file)
Maintainer  : cdep.illabout@gmail.com
Stability   : experimental
Portability : POSIX

= Password Validation

It is common for passwords to have a set of requirements. For example,
a password might have to contain at least a certain amount of characters
that consist of uppercase and lowercase alphabetic characters combined with
numbers and/or other special characters.

This module provides an API which enables you to set up your own
'PasswordPolicy' to validate the format of 'Password's.

== Password Policies

The most important part is to have a valid and robust 'PasswordPolicy'.

A 'defaultPasswordPolicy_' is provided to quickly set up a "good-enough"
validation of passwords, but you can also adjust it, or just create your
own.

Just remember that a 'PasswordPolicy' must be validated first to make
sure it is actually a 'ValidPasswordPolicy'. Otherwise, you'd never be
able to validate any given 'Password's.

= Example usage

So let's say we're fine with the default policy, which requires the
password to be between 8-64 characters, and have at least one lowercase,
one uppercase and one digit character, then our function would look like
the following:

@
myValidateFunc :: 'Password' -> Bool
myValidateFunc = 'isValidPassword' 'defaultPasswordPolicy_'
@

== Custom policies

But, for example, if you'd like to enforce that a 'Password' includes
at least one special character, and be at least 12 characters long,
you'll have to make your own 'PasswordPolicy'.

@
customPolicy :: 'PasswordPolicy'
customPolicy =
  'defaultPasswordPolicy'
    { minimumLength = 12
    , specialChars = 1
    }
@

This custom policy will then have to be validated first, so it can be
used to validate 'Password's further on.

== Template Haskell

The easiest way to validate a custom 'PasswordPolicy' is by using a
Template Haskell splice.
Just turn on the @\{\-\# LANGUAGE TemplateHaskell \#\-\}@ pragma, pass your
policy to 'validatePasswordPolicyTH', surround it by @\$(...)@ and if
it compiles it will be a 'ValidPasswordPolicy'.

@
{-\# LANGUAGE TemplateHaskell \#-}
customValidPolicy :: 'ValidPasswordPolicy'
customValidPolicy = $('validatePasswordPolicyTH' customPolicy)
@

__NB: any custom 'CharSetPredicate' will be ignored by 'validatePasswordPolicyTH'__
__and replaced with the 'defaultCharSetPredicate'.__
So if you want to use your own 'CharSetPredicate', you won't be able
to validate your policy using 'validatePasswordPolicyTH'. Most users,
however, will find 'defaultCharSetPredicate' to be sufficient.

== At runtime

Another way of validating your custom policy is 'validatePasswordPolicy'.
In an application, this might be implemented in the following way.

@
main :: IO ()
main =
    case ('validatePasswordPolicy' customPolicy) of
      Left reasons -> error $ show reasons
      Right validPolicy -> app \`runReaderT\` validPolicy

customValidateFunc :: 'Password' -> ReaderT 'ValidPasswordPolicy' IO Bool
customValidateFunc pwd = do
    policy <- ask
    return $ 'isValidPassword' policy pwd
@

== Let's get dangerous

Or, if you like living on the edge, you could also just match on 'Right'.
I hope you're certain your policy is valid, though. So please have at least
a unit test to verify that passing your 'PasswordPolicy' to
'validatePasswordPolicy' actually returns a 'Right'.

@
Right validPolicy = 'validatePasswordPolicy' customPolicy

customValidateFunc :: 'Password' -> Bool
customValidateFunc = 'isValidPassword' validPolicy
@

-}

module Data.Password.Validate
  ( -- * Validating passwords
    --
    -- |
    -- The main function of this module is probably 'isValidPassword',
    -- as it is simple and straightforward.
    --
    -- Though if you'd want to know why a 'Password' failed to validate,
    -- because you'd maybe like to communicate those 'InvalidReason's
    -- back to the user, 'validatePassword' is here to help you out.
    validatePassword,
    isValidPassword,
    ValidationResult(..),
    -- ** Password Policy
    --
    -- |
    -- A 'PasswordPolicy' has to be validated before it can be used to validate a
    -- 'Password'.
    -- This is done using 'validatePasswordPolicy' or 'validatePasswordPolicyTH'.
    --
    -- Next to the obvious lower and upper bounds for the length of a 'Password',
    -- a 'PasswordPolicy' can dictate how many lowercase letters, uppercase letters,
    -- digits and/or special characters are minimally required to be used in the
    -- 'Password' to be considered a valid 'Password'.
    --
    -- An observant user might have also seen that a 'PasswordPolicy' includes a
    -- 'CharSetPredicate'. Very few users will want to change this from the
    -- 'defaultCharSetPredicate', since this includes all non-control ASCII characters.
    --
    -- If, for some reason, you'd like to accept more characters (e.g. é, ø, か, 事)
    -- or maybe you want to only allow alpha-numeric characters, 'charSetPredicate' is
    -- the place to do so.
    validatePasswordPolicy,
    validatePasswordPolicyTH,
    PasswordPolicy (..),
    ValidPasswordPolicy,
    fromValidPasswordPolicy,
    defaultPasswordPolicy,
    defaultPasswordPolicy_,
    CharSetPredicate(..),
    defaultCharSetPredicate,
    InvalidReason (..),
    InvalidPolicyReason(..),
    CharacterCategory(..),
    MinimumLength,
    MaximumLength,
    ProvidedLength,
    MinimumAmount,
    ProvidedAmount,
    -- * For internal use
    --
    -- | These are used in the test suite. You should not need these.
    --
    -- These are basically internal functions and as such have NO guarantee (__NONE__)
    -- to be consistent between releases.
    defaultCharSet,
    validateCharSetPredicate,
    categoryToPredicate,
    isSpecial,
    allButCSP
  ) where

import Data.Char (chr, isAsciiLower, isAsciiUpper, isDigit, ord)
import Data.Function (on)
import Data.List (foldl')

#if !MIN_VERSION_base(4,13,0)
import Data.Semigroup ((<>))
#endif
import Data.Text (Text)
import qualified Data.Text as T
import Language.Haskell.TH (Exp, Q, appE)
import Language.Haskell.TH.Syntax (Lift (..))

import Data.Password.Internal (Password (..))

-- $setup
-- >>> :set -XOverloadedStrings
--
-- Import needed libraries.
--
-- >>> import Data.Password

-- | Set of policies used to validate a 'Password'.
--
-- When defining your own 'PasswordPolicy', please keep in mind that:
--
-- * The value of 'maximumLength' must be bigger than 0
-- * The value of 'maximumLength' must be bigger than 'minimumLength'
-- * If any other field has a negative value (e.g. 'lowercaseChars'), it will be defaulted to 0
-- * The total sum of all character category values (i.e. all fields ending in @-Chars@)
--   must not be larger than the value of 'maximumLength'.
-- * The provided 'CharSetPredicate' needs to allow at least one of the characters in the
--   categories which require more than 0 characters. (e.g. if 'lowercaseChars' is > 0,
--   the 'charSetPredicate' must allow at least one of the characters in @[\'a\'..\'z\']@)
--
-- or else the validation functions will return one or more 'InvalidPolicyReason's.
--
-- If you're unsure of what to do, please use the default: 'defaultPasswordPolicy_'
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

-- NB: KEEP THIS THE SAME ORDER AS THE PasswordPolicy FIELDS!
-- OTHERWISE THE 'validatePasswordPolicyTH' FUNCTION WILL BREAK.

-- @since 2.1.0.0
-- | All 'Int' fields of the 'PasswordPolicy' in a row
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
  { fromValidPasswordPolicy :: PasswordPolicy
    -- ^
    -- In case you'd want to retrieve the 'PasswordPolicy'
    -- from the 'ValidPasswordPolicy'
    --
    -- @since 2.1.0.0
  } deriving (Eq, Ord, Show)

-- | Default value for the 'PasswordPolicy'.
--
-- Enforces that a password must be between 8-64 characters long and
-- have at least one uppercase letter, one lowercase letter and one digit,
-- though can easily be adjusted by using record update syntax:
--
-- @
-- myPolicy = defaultPasswordPolicy{ specialChars = 1 }
-- @
--
-- This policy on it's own is guaranteed to be valid. Any changes made to
-- it might result in 'validatePasswordPolicy' returning one or more
-- 'InvalidPolicyReason's.
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
-- and special characters from the @ASCII@ character set.
-- (i.e. everything from the @ASCII@ set except the control characters)
--
-- @since 2.1.0.0
defaultCharSetPredicate :: CharSetPredicate
defaultCharSetPredicate =  CharSetPredicate $ \c -> ord c >= 32 && ord c <= 126
{-# INLINE defaultCharSetPredicate #-}

-- @since 2.1.0.0
-- | Check if given 'Char' is a special character.
-- (i.e. any non-alphanumeric non-control ASCII character)
isSpecial :: Char -> Bool
isSpecial = \c ->
    isDefault c && not (isAsciiUpper c || isAsciiLower c || isDigit c)
  where
    CharSetPredicate isDefault = defaultCharSetPredicate

-- | Character categories
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

-- @since 2.1.0.0
-- | Convert a 'CharacterCategory' into its associated predicate function
categoryToPredicate :: CharacterCategory -> (Char -> Bool)
categoryToPredicate = \case
  Uppercase -> isAsciiUpper
  Lowercase -> isAsciiLower
  Special -> isSpecial
  Digit -> isDigit

type MinimumLength = Int
type MaximumLength = Int
type ProvidedLength = Int
type MinimumAmount = Int
type ProvidedAmount = Int

-- | Possible reasons for a 'Password' to be invalid.
--
-- @since 2.1.0.0
data InvalidReason
  = PasswordTooShort !MinimumLength !ProvidedLength
  -- ^ Length of 'Password' is too short.
  | PasswordTooLong !MaximumLength !ProvidedLength
  -- ^ Length of 'Password' is too long.
  | NotEnoughReqChars !CharacterCategory !MinimumAmount !ProvidedAmount
  -- ^ 'Password' does not contain required number of characters.
  | InvalidCharacters !Text
  -- ^ 'Password' contains characters that cannot be used
  deriving (Eq, Ord, Show)

-- | Possible reasons for a 'PasswordPolicy' to be invalid
--
-- @since 2.1.0.0
data InvalidPolicyReason
  = InvalidLength !MinimumLength !MaximumLength
  -- ^ Value of 'minimumLength' is bigger than 'maximumLength'
  --
  -- @InvalidLength minimumLength maximumLength@
  | MaxLengthBelowZero !MaximumLength
  -- ^ Value of 'maximumLength' is zero or less
  --
  -- @MaxLengthBelowZero maximumLength@
  | CategoryAmountsAboveMaxLength !MaximumLength !Int
  -- ^ The total of the character category amount requirements are
  -- higher than the maximum length of the password. (i.e. the 'Int' signifies
  -- the total of 'lowercaseChars' + 'uppercaseChars' + 'digitChars' + 'specialChars')
  --
  -- @CategoryAmountsAboveMaxLength maximumLength totalRequiredChars@
  | InvalidCharSetPredicate !CharacterCategory !MinimumAmount
  -- ^ 'charSetPredicate' does not return 'True' for a 'CharacterCategory' that
  -- requires at least 'MinimumAmount' characters in the password
  deriving (Eq, Ord, Show)

-- | Result of validating a 'Password'.
--
-- @since 2.1.0.0
data ValidationResult = ValidPassword | InvalidPassword [InvalidReason]
  deriving (Eq, Show)

-- | This function is equivalent to:
--
-- @'validatePassword' policy password == 'ValidPassword'@
--
-- >>> let pass = mkPassword "This_Is_Valid_PassWord1234"
-- >>> isValidPassword defaultPasswordPolicy_ pass
-- True
--
-- @since 2.1.0.0
isValidPassword :: ValidPasswordPolicy -> Password -> Bool
isValidPassword policy pass = validatePassword policy pass == ValidPassword
{-# INLINE isValidPassword #-}

-- | Checks if a given 'Password' adheres to the provided 'ValidPasswordPolicy'.
--
-- In case of an invalid password, returns the reasons why it wasn't valid.
--
-- >>> let pass = mkPassword "This_Is_Valid_Password1234"
-- >>> validatePassword defaultPasswordPolicy_ pass
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

-- | Template Haskell validation function for 'PasswordPolicy's.
--
-- @
-- {-\# LANGUAGE TemplateHaskell \#-}
-- myPolicy :: 'PasswordPolicy'
-- myPolicy = 'defaultPasswordPolicy'{ specialChars = 1 }
--
-- myValidPolicy :: 'ValidPasswordPolicy'
-- myValidPolicy = $('validatePasswordPolicyTH' myPolicy)
-- @
--
-- For technical reasons, the 'charSetPredicate' field is ignored and the
-- 'defaultCharSetPredicate' is used. If, for any reason, you do need to use a
-- custom 'CharSetPredicate', please use 'validatePasswordPolicy' and either handle
-- the failure case at runtime and/or use a unit test to make sure your policy is valid.
--
-- @since 2.1.0.0
validatePasswordPolicyTH :: PasswordPolicy -> Q Exp
validatePasswordPolicyTH pp =
    either (fail . showReasons) go $ validatePasswordPolicy withDefault
  where
    withDefault = pp{charSetPredicate = defaultCharSetPredicate}
    showReasons rs = "Bad password policy: " ++ show rs
    go _ = [|VPP|] `appE` newPP
    allButCSPQ = lift <$> allButCSP withDefault
    newPP = foldl' appE [|PasswordPolicy|] allButCSPQ `appE` [|defaultCharSetPredicate|]

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
    allReasons = mconcat [validMaxLength, validLength, validCategoryAmount, validPredicate]
    validLength, validMaxLength, validCategoryAmount, validPredicate :: [InvalidPolicyReason]
    validLength =
        [InvalidLength minimumLength maximumLength | minimumLength > maximumLength]
    validMaxLength =
        [MaxLengthBelowZero maximumLength | maximumLength <= 0]
    validCategoryAmount =
        -- We don't report this reason if the maximumLength is already invalid
        [CategoryAmountsAboveMaxLength maximumLength total | total > maximumLength, maximumLength > 0]
      where
        capToZero = max 0
        total = sum $ capToZero <$> [lowercaseChars, uppercaseChars, digitChars, specialChars]
    validPredicate = validateCharSetPredicate policy

-- @since 2.1.0.0
-- | Default character set
--
-- Should be all non-control characters in the ASCII character set.
defaultCharSet :: String
defaultCharSet = chr <$> [32 .. 126]
