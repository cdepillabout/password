module Scrypt where

import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import qualified Crypto.Scrypt as Scrypt
import Data.Password.Types
import Data.Password.Scrypt

import TestUtils


testScrypt :: TestTree
testScrypt = testGroup "scrypt"
  [ testCorrectPassword "Scrypt (hashPassword)" hash8Rounds checkPassword extractParams testParams
  , testIncorrectPassword "Scrypt (hashPassword) fail" hash8Rounds checkPassword
  , testWithSalt "Scrypt (hashPasswordWithSalt)"
                 (hashPasswordWithSalt testParams)
                 checkPassword
                 extractParams
                 testParams
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 checkScrypt
  ]
  where
    hash8Rounds = hashPasswordWithParams testParams
    testParams = defaultParams{ scryptRounds = 8 }

checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 8 8 1
      Scrypt.EncryptedPass scryptHash =
        Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PasswordHash ourHash =
        hashPasswordWithSalt defaultParams{ scryptRounds = 8 } (Salt salt) $ mkPassword pass
  return $ scryptHash === encodeUtf8 ourHash
