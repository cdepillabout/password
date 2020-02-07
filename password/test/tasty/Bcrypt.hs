{-# OPTIONS_GHC -Wno-orphans #-}
module Bcrypt where

import Data.ByteArray (pack)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password
import Data.Password.Bcrypt

testBcrypt :: TestTree
testBcrypt = testGroup "bcrypt"
  [ testProperty "Bcrypt (hashPass)" $ \pass -> run10 $ do
      let pw = mkPass pass
      hpw <- hashPass pw
      return $ checkPass pw hpw === PassCheckSuccess
  , testProperty "Bcrypt (hashPass) fail" $ \pass pass2 -> run10 $ do
      let pw = mkPass pass
          pw2 = mkPass pass2
          result = if pass == pass2 then PassCheckSuccess else PassCheckFail
      hpw <- hashPass pw
      return $ checkPass pw2 hpw === result
  , testProperty "Bcrypt (hashPassWithSalt)" $ \pass salt -> withMaxSuccess 10 $
      let pw = mkPass pass
          hpw = hashPassWithSalt 12 salt pw
      in checkPass pw hpw === PassCheckSuccess
  ]
  where
    run10 = withMaxSuccess 10 . ioProperty

instance Arbitrary (Salt a) where
  arbitrary = Salt . pack <$> vector 16
