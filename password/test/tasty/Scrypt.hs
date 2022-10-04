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

import Internal


testScrypt :: TestTree
testScrypt = testGroup "scrypt"
  [ testCorrectPassword "Scrypt (hashPassword, 8 rounds)" hash8Rounds checkPassword extractParams testsParams8Rounds
  , testCorrectPassword "Scrypt (hashPassword, 16 rounds)" hash16Rounds checkPassword extractParams testsParams16Rounds
  , testIncorrectPassword "Scrypt (hashPassword) fail" hash8Rounds checkPassword
  , testWithSalt "Scrypt (hashPasswordWithSalt)"
                 (hashPasswordWithSalt testsParams8Rounds)
                 checkPassword
                 extractParams
                 testsParams8Rounds
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 checkScrypt
  ]
  where
    hash8Rounds = hashPasswordWithParams testsParams8Rounds
    testsParams8Rounds = defaultParams{ scryptRounds = 8 }
    hash16Rounds = hashPasswordWithParams testsParams16Rounds
    testsParams16Rounds = defaultParams{ scryptRounds = 16 }

checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 8 8 1
      Scrypt.EncryptedPass scryptHash =
        Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PasswordHash ourHash =
        hashPasswordWithSalt defaultParams{ scryptRounds = 8 } (Salt salt) $ mkPassword pass
  return $ scryptHash === encodeUtf8 ourHash
