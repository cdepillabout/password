{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -Wno-orphans #-}
module Internal where

import Data.ByteArray (pack)
import Data.Text (Text)
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
testIncorrectPassword s hashF checkF =
    testProperty s $ testIncorrectPassword' hashF checkF

-- Similar to 'testIncorrectPassword', but exempts the comparison of
-- "" and "\NUL", since 'bcrypt' and 'PBKDF2' match those as well.
testIncorrectPassword_ :: String
                       -> (Password -> IO (PasswordHash a))
                       -> (Password -> PasswordHash a -> PasswordCheck)
                       -> TestTree
testIncorrectPassword_ s hashF checkF =
    testProperty s $ \pass pass2 ->
      not (all isEmpty [pass, pass2]) ==>
        testIncorrectPassword' hashF checkF pass pass2
  where
    isEmpty c = c `elem` ["", "\NUL"]

testIncorrectPassword' :: (Password -> IO (PasswordHash a))
                       -> (Password -> PasswordHash a -> PasswordCheck)
                       -> Text -> Text -> Property
testIncorrectPassword' hashF checkF pass pass2 = run10 $ do
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
