module Scrypt where

import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import qualified Crypto.Scrypt as Scrypt
import Data.Password
import Data.Password.Scrypt

import Internal


testScrypt :: TestTree
testScrypt = testGroup "scrypt"
  [ testCorrectPass "Scrypt (hashPass)" hashPass checkPass
  , testIncorrectPass "Scrypt (hashPass) fail" hashPass checkPass
  , testWithSalt "Scrypt (hashPassWithSalt)" (hashPassWithSalt defaultParams) checkPass
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 $ checkScrypt
  ]

checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 16 8 1
      Scrypt.EncryptedPass scryptHash = Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PassHash ourHash = hashPassWithSalt defaultParams (Salt salt) $ mkPass pass
  return $ scryptHash === encodeUtf8 ourHash
