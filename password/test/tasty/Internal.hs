{-# OPTIONS_GHC -Wno-orphans #-}
module Internal where

import Data.ByteArray (pack)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password


testCorrectPassword :: String
                    -> (Password -> IO (PasswordHash a))
                    -> (Password -> PasswordHash a -> PasswordCheck)
                    -> TestTree
testCorrectPassword s hashF checkF = testProperty s $
  \pass -> run10 $ do
    let pw = mkPassword pass
    hpw <- hashF pw
    return $ checkF pw hpw === PasswordCheckSuccess

testIncorrectPassword :: String
                      -> (Password -> IO (PasswordHash a))
                      -> (Password -> PasswordHash a -> PasswordCheck)
                      -> TestTree
testIncorrectPassword s hashF checkF = testProperty s $
  \pass pass2 -> run10 $ do
    let pw = mkPassword pass
        pw2 = mkPassword pass2
        result = if pass == pass2 then PasswordCheckSuccess
                                  else PasswordCheckFail
    hpw <- hashF pw
    return $ checkF pw2 hpw === result

testWithSalt :: String
             -> (Salt a -> Password -> PasswordHash a)
             -> (Password -> PasswordHash a -> PasswordCheck)
             -> TestTree
testWithSalt s hashWithSalt checkF = testProperty s $
  \pass salt -> withMaxSuccess 10 $
    let pw = mkPassword pass
        hpw = hashWithSalt salt pw
    in checkF pw hpw === PasswordCheckSuccess

run10 :: Testable prop => IO prop -> Property
run10 = withMaxSuccess 10 . ioProperty

instance Arbitrary (Salt a) where
  arbitrary = Salt . pack <$> vector 16
