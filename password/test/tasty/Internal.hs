{-# OPTIONS_GHC -Wno-orphans #-}
module Internal where

import Data.ByteArray (pack)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password


testCorrectPass :: String -> (Pass -> IO (PassHash a)) -> (Pass -> PassHash a -> PassCheck) -> TestTree
testCorrectPass s hashF checkF = testProperty s $
  \pass -> run10 $ do
    let pw = mkPass pass
    hpw <- hashF pw
    return $ checkF pw hpw === PassCheckSuccess

testIncorrectPass :: String -> (Pass -> IO (PassHash a)) -> (Pass -> PassHash a -> PassCheck) -> TestTree
testIncorrectPass s hashF checkF = testProperty s $
  \pass pass2 -> run10 $ do
    let pw = mkPass pass
        pw2 = mkPass pass2
        result = if pass == pass2 then PassCheckSuccess else PassCheckFail
    hpw <- hashF pw
    return $ checkF pw2 hpw === result

testWithSalt :: String -> (Salt a -> Pass -> PassHash a) -> (Pass -> PassHash a -> PassCheck) -> TestTree
testWithSalt s hashWithSalt checkF = testProperty s $
  \pass salt -> withMaxSuccess 10 $
    let pw = mkPass pass
        hpw = hashWithSalt salt pw
    in checkF pw hpw === PassCheckSuccess

run10 :: Testable prop => IO prop -> Property
run10 = withMaxSuccess 10 . ioProperty

instance Arbitrary (Salt a) where
  arbitrary = Salt . pack <$> vector 16
