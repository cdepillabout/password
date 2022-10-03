{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Internal where

import Data.ByteArray (pack)
import Data.Maybe (isJust)
import Test.Tasty (TestTree)
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (mkPassword, Password, PasswordHash)
import Data.Password.Bcrypt (PasswordCheck(..), Salt(..))


testCorrectPassword :: String
                    -> (Password -> IO (PasswordHash a))
                    -> (Password -> PasswordHash a -> PasswordCheck)
                    -> (PasswordHash a -> Maybe params)
                    -> TestTree
testCorrectPassword s hashF checkF extractParamsF = testProperty s $
  \pass -> ioProperty $ do
    let pw = mkPassword pass
    hpw <- hashF pw
    return $ (checkF pw hpw === PasswordCheckSuccess) .&&. isJust (extractParamsF hpw) === True

testIncorrectPassword :: String
                      -> (Password -> IO (PasswordHash a))
                      -> (Password -> PasswordHash a -> PasswordCheck)
                      -> TestTree
testIncorrectPassword s hashF checkF = testProperty s $
  \pass pass2 -> pass /= pass2 && not (all isEmpty [pass, pass2]) ==>
    ioProperty $ do
      let pw = mkPassword pass
          pw2 = mkPassword pass2
      hpw <- hashF pw
      return $ checkF pw2 hpw === PasswordCheckFail
  where
    isEmpty c = c `elem` ["", "\NUL"]

testWithSalt :: String
             -> (Salt a -> Password -> PasswordHash a)
             -> (Password -> PasswordHash a -> PasswordCheck)
             -> (PasswordHash a -> Maybe params)
             -> TestTree
testWithSalt s hashWithSalt checkF extractParamsF = testProperty s $
  \pass salt ->
    let pw = mkPassword pass
        hpw = hashWithSalt salt pw
    in (checkF pw hpw === PasswordCheckSuccess) .&&. isJust (extractParamsF hpw) === True

instance Arbitrary (Salt a) where
  arbitrary = Salt . pack <$> vector 16
