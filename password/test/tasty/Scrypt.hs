{-# LANGUAGE CPP #-}
{-# LANGUAGE OverloadedStrings #-}
module Scrypt where

import Data.ByteString (fromStrict)
import Data.Maybe (fromJust)
import Data.Text (Text)
import Data.Text.Encoding (encodeUtf8)
import Test.Tasty
import Test.Tasty.Golden (goldenVsString)
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

#ifndef IS_MAC_OS
import qualified Crypto.Scrypt as Scrypt
#endif
import Data.Password.Types
import Data.Password.Scrypt

import Internal


testScrypt :: TestTree
testScrypt = testGroup "scrypt"
  [ testCorrectPassword "Scrypt (hashPassword, 8 rounds)" hash8Rounds checkPassword extractParams testsParams8Rounds
  , testCorrectPassword "Scrypt (hashPassword, 4 rounds)" hash4Rounds checkPassword extractParams testsParams4Rounds
  , testIncorrectPassword "Scrypt (hashPassword) fail" hash8Rounds checkPassword
  , testWithSalt "Scrypt (hashPasswordWithSalt)"
                 (hashPasswordWithSalt testsParams8Rounds)
                 checkPassword
                 extractParams
                 testsParams8Rounds
#ifndef IS_MAC_OS
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 checkScrypt
#endif
  , testGolden
  ]
  where
    hash8Rounds = hashPasswordWithParams testsParams8Rounds
    testsParams8Rounds = defaultParams{ scryptRounds = 8, scryptSalt = 16 }
    hash4Rounds = hashPasswordWithParams testsParams4Rounds
    testsParams4Rounds = defaultParams{ scryptRounds = 4, scryptSalt = 16 }

#ifndef IS_MAC_OS
checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 8 8 1
      Scrypt.EncryptedPass scryptHash =
        Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PasswordHash ourHash =
        hashPasswordWithSalt defaultParams{ scryptRounds = 8 } (Salt salt) $ mkPassword pass
  return $ scryptHash === encodeUtf8 ourHash
#endif

testGolden :: TestTree
testGolden = testGroup "Golden tests"
    [ go "defaultParams" "Scrypt_defaultParams" defaultParams "somesalt42"
    , go "rounds = 8" "Scrypt_rounds8" defaultParams{scryptRounds = 8} "somesalt42"
    , go "output length = 16" "Scrypt_outputLength16" defaultParams{scryptOutputLength = 16} "somesalt42"
    , go "scrypt length = 16" "Scrypt_saltLength16" defaultParams{scryptSalt = 16} "somesalt42"
    , go "Other salt" "Scrypt_otherSalt" defaultParams "somesalt0"
    ]
  where go testName fileName params salt =
          goldenVsString
            testName
            ("test/golden/" <> fileName <> ".golden")
            (return $ fromStrict $ encodeUtf8 $ unPasswordHash $ hashPasswordWithSalt params (Salt salt) $ mkPassword "password")
