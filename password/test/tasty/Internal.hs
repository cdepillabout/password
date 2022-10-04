{-# LANGUAGE OverloadedStrings #-}
module Internal (testInternal) where

import qualified Data.ByteString as B
import Data.Text.Encoding(encodeUtf8)
import Data.ByteString.Base64 (encodeBase64)
import Data.Word (Word16)
import Test.Tasty (TestTree, testGroup)
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password.Bcrypt (Salt(..))

import Data.Password.Internal


testInternal :: TestTree
testInternal = testGroup "Internal"
  [ newSaltTest
  , padding64Test
  ]

newSaltTest :: TestTree
newSaltTest =
  testProperty "newSalt <-> length salt" $
    \i -> ioProperty $ do
      let n = fromIntegral (i :: Word16)
      Salt salt <- newSalt n
      pure $ B.length salt === n

padding64Test :: TestTree
padding64Test =
  testProperty "unsafePad64 <-> unsafeRemovePad64" $
    \it -> let i = encodeUtf8 it
               bs = encodeBase64 i
           in unsafeRemovePad64 (B.length i) (unsafePad64 bs) === bs
