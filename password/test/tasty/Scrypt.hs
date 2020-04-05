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
  [ testCorrectPassword "Scrypt (hashPassword)" hashPassword checkPassword
  , testIncorrectPassword "Scrypt (hashPassword) fail" hashPassword checkPassword
  , testWithSalt "Scrypt (hashPasswordWithSalt)"
                 (hashPasswordWithSalt defaultParams)
                 checkPassword
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 $ checkScrypt
  ]

checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 16 8 1
      Scrypt.EncryptedPass scryptHash =
        Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PasswordHash ourHash =
        hashPasswordWithSalt defaultParams (Salt salt) $ mkPassword pass
  return $ scryptHash === encodeUtf8 ourHash
