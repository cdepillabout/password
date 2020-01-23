import Crypto.Scrypt (Salt(..))
import Data.Text.Encoding (encodeUtf8)
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password

main :: IO ()
main = defaultMain $ testGroup "Password"
  [ testProperty "Pass" $ \pass ->
      unsafeShowPasswordText (mkPass pass) === pass
  , testProperty "Scrypt (hashPass)" $ \pass -> ioProperty $ do
      let pw = mkPass pass
      hpw <- hashPass pw
      return $ checkPass pw hpw === PassCheckSuccess
  , testProperty "Scrypt (hashPass) fail" $ \pass pass2 -> ioProperty $ do
      let pw = mkPass pass
          pw2 = mkPass pass2
          result = if pass == pass2 then PassCheckSuccess else PassCheckFail
      hpw <- hashPass pw
      return $ checkPass pw2 hpw === result
  , testProperty "Scrypt (hashPassWithSalt)" $ \pass salt ->
      let pw = mkPass pass
          hpw = hashPassWithSalt (Salt $ encodeUtf8 salt) pw
      in checkPass pw hpw === PassCheckSuccess
  ]
