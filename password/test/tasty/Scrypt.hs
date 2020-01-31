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


testScrypt :: TestTree
testScrypt = testGroup "scrypt"
  [ testProperty "Scrypt (hashPass)" $ \pass -> run10 $ do
      let pw = mkPass pass
      hpw <- hashPass pw
      return $ checkPass pw hpw === PassCheckSuccess
  , testProperty "Scrypt (hashPass) fail" $ \pass pass2 -> run10 $ do
      let pw = mkPass pass
          pw2 = mkPass pass2
          result = if pass == pass2 then PassCheckSuccess else PassCheckFail
      hpw <- hashPass pw
      return $ checkPass pw2 hpw === result
  , testProperty "Scrypt (hashPassWithSalt)" $ \pass salt -> withMaxSuccess 10 $
      let pw = mkPass pass
          hpw = hashPassWithSalt defaultParams (Salt $ encodeUtf8 salt) pw
      in checkPass pw hpw === PassCheckSuccess
  , testProperty "scrypt <-> cryptonite" $ withMaxSuccess 10 $ checkScrypt
  ]
  where
    run10 = withMaxSuccess 10 . ioProperty

checkScrypt :: Text -> Property
checkScrypt pass = ioProperty $ do
  s@(Scrypt.Salt salt) <- Scrypt.newSalt
  let params = fromJust $ Scrypt.scryptParams 16 8 1
      Scrypt.EncryptedPass scryptHash = Scrypt.encryptPass params s $ Scrypt.Pass $ encodeUtf8 pass
      PassHash ourHash = hashPassWithSalt defaultParams (Salt salt) $ mkPass pass
  return $ scryptHash === encodeUtf8 ourHash
