{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Internal where

import Data.ByteArray (pack)
import Test.Tasty (TestTree)
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Types (mkPassword, Password, PasswordHash)
import Data.Password.Bcrypt (PasswordCheck(..), Salt(..))


testCorrectPassword :: (Eq params, Show params)
                    => String
                    -> (Password -> IO (PasswordHash a))
                    -> (Password -> PasswordHash a -> PasswordCheck)
                    -> (PasswordHash a -> Maybe params)
                    -> params
                    -> TestTree
testCorrectPassword s hashF checkF extractParamsF params = testProperty s $
  \pass -> ioProperty $ do
    let pw = mkPassword pass
    hpw <- hashF pw
    return $ (checkF pw hpw === PasswordCheckSuccess) .&&. extractParamsF hpw === Just params

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

testWithSalt :: (Eq params, Show params)
             => String
             -> (Salt a -> Password -> PasswordHash a)
             -> (Password -> PasswordHash a -> PasswordCheck)
             -> (PasswordHash a -> Maybe params)
             -> params
             -> TestTree
testWithSalt s hashWithSalt checkF extractParamsF params = testProperty s $
  \pass salt ->
    let pw = mkPassword pass
        hpw = hashWithSalt salt pw
    in (checkF pw hpw === PasswordCheckSuccess) .&&. extractParamsF hpw === Just params

instance Arbitrary (Salt a) where
  arbitrary = Salt . pack <$> vector 16
