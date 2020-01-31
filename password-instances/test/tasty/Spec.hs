import Database.Persist.Class (PersistField(..))
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.QuickCheck.Instances.Text ()

import Data.Password (PassHash(..))
import Data.Password.Instances()

main :: IO ()
main = defaultMain $ testGroup "Password Instances"
  [ testProperty "PassHash (PersistField)" $ \pass ->
      let pwd = PassHash pass
      in fromPersistValue (toPersistValue pwd) === Right pwd
  ]
