{-# LANGUAGE LambdaCase #-}

module Data.Password.Validate
  ( PasswordPolicy(..)
  , PolicyCharReq(..)
  , PolicyCharSet
  , FailedPolicies(..)
  , defaultPasswordPolicy
  , validatePassword'
  , validatePassword
  , specialChars
  ) where

import Data.Password.Internal
import qualified Data.Text as T
import Data.List (foldl')
import Data.Char (isAscii, isUpper, isLower)

-- TODO: Create code for checking that plain-text passwords conform to some sort of
-- password policy.

data PasswordPolicy = PasswordPolicy
  { passPolicyLength :: Int
  , passPolicyCharReqs :: [PolicyCharReq]
  , passPolicyCharSet :: PolicyCharSet
  } deriving (Show)

-- | Character requirements for a password policy.
data PolicyCharReq
  = PolicyCharReqUpper Int
  -- ^ A password requires at least 'Int' upper-case characters.
  | PolicyCharReqLower Int
  -- ^ A password requires at least 'Int' lower-case characters.
  | PolicyCharReqSpecial Int
  -- ^ A password requires at least 'Int' special characters
  deriving (Show)

data PolicyCharSet = PolicyCharSetAscii
  deriving Show

-- | Perhaps use Default typeclass?
defaultPasswordPolicy :: PasswordPolicy
defaultPasswordPolicy = PasswordPolicy
     { passPolicyLength = 10,
       passPolicyCharReqs = [PolicyCharReqUpper 1, PolicyCharReqLower 1, PolicyCharReqSpecial 1],
       passPolicyCharSet = PolicyCharSetAscii
     }

-- | Data type representing how password has failed
data FailedPolicies
  = NotEnoughLength Int Int
  -- ^ Given password did not have enough length
  | DoesNotFillCharReq [PolicyCharReq]
  -- ^ Given password did not fill one of the char requirements
  | InvalidChar PolicyCharSet
  -- ^ Invalid Character was used
  deriving (Show)

-- | Check if given 'Password' fills all the Policies,
-- return true if given password is valid
validatePassword' :: Password -> PasswordPolicy -> Bool
validatePassword' password policy = null $ validatePassword password policy

-- | Check if given 'Password' fills all the Policies, returns list of 
-- policies that failed.
validatePassword :: Password -> PasswordPolicy -> [FailedPolicies]
validatePassword (Password password) (PasswordPolicy passLength charReqs set) =
  foldl'
    accum
    mempty
    [ hasEnoughLength
    , isUsingPolicyCharSet
    , isFillingRequirements
    ]
  where
    accum :: [FailedPolicies] -> Maybe FailedPolicies -> [FailedPolicies]
    accum fs mFailedPolicies = maybe fs (\failedPolicy -> failedPolicy : fs) mFailedPolicies
    hasEnoughLength :: Maybe FailedPolicies
    hasEnoughLength = if T.length password < passLength
      then Just $ NotEnoughLength (T.length password) passLength
      else Nothing
    isUsingPolicyCharSet :: Maybe FailedPolicies
    isUsingPolicyCharSet = case set of
      PolicyCharSetAscii -> if T.all isAscii password
        then Nothing
        else Just $ InvalidChar PolicyCharSetAscii
    isFillingRequirements :: Maybe FailedPolicies
    isFillingRequirements = 
      let failedCharReqs = foldr (\req list -> checkReqs req list) mempty charReqs
      in if null failedCharReqs
        then Nothing
        else Just $ DoesNotFillCharReq failedCharReqs
    checkReqs :: PolicyCharReq -> [PolicyCharReq] -> [PolicyCharReq]
    checkReqs req ls = case req of
      PolicyCharReqUpper _ -> checkCharReq isUpper req ls
      PolicyCharReqLower _ -> checkCharReq isLower req ls
      PolicyCharReqSpecial _ -> checkCharReq (\char -> char `elem` specialChars) req ls
    checkCharReq :: (Char -> Bool) -> PolicyCharReq -> [PolicyCharReq] -> [PolicyCharReq]
    checkCharReq predicate req ls = 
      let num = T.length $ T.filter predicate password
      in if num < (getRequiredNum req)
        then req : ls
        else ls
    getRequiredNum :: PolicyCharReq -> Int
    getRequiredNum  = \case 
      PolicyCharReqLower num -> num
      PolicyCharReqUpper num -> num
      PolicyCharReqSpecial num -> num

-- https://www.ipvoid.com/password-special-characters/
-- https://owasp.org/www-community/password-special-characters
specialChars :: [Char]
specialChars = " !\"#$%&'()*+,-./:;<=>?@[]^_`{|}~"