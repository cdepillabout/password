{-# LANGUAGE CPP #-}
import Test.Tasty
import Test.Tasty.QuickCheck
import Test.Tasty.Runners (NumThreads(..))

import Data.Password.Types

import Argon2 (testArgon2)
import Bcrypt (testBcrypt)
import PBKDF2 (testPBKDF2)
import Scrypt (testScrypt)
import Validate (testValidate)

#if INTERNALTEST
import Data.ByteString as B (length)
import Data.ByteString.Base64 (encodeBase64)
import Data.Text (Text)
import qualified Data.Text as T (cons, filter, length, null)
import Data.Word (Word16)
import Data.Password.Internal
#endif

main :: IO ()
main = defaultMain $ localOption (NumThreads 1) $
  testGroup "Password"
    [ testProperty "Password" $ \pass ->
        unsafeShowPassword (mkPassword pass) === pass
    , testArgon2
    , testBcrypt
    , testPBKDF2
    , testScrypt
    , testValidate
#if INTERNALTEST
    , testInternals
#endif
    ]

#if INTERNALTEST
testInternals :: TestTree
testInternals =
    testGroup
        "Internals"
        [ testSaltSize
        , testUnsafePadding64
        , testUnsafePadding64_2
        ]

-- Check that the invariant:
-- "number given to 'newSalt' is indeed the amount of bytes in the salt"
testSaltSize :: TestTree
testSaltSize =
    testProperty "newSalt n ==> length salt == n" $ \n ->
        ioProperty $ do
            let i = fromIntegral (n :: Word16)
            Salt salt <- newSalt i
            pure $ B.length salt === i

-- Check that unpadding and padding is consistent
testUnsafePadding64 :: TestTree
testUnsafePadding64 =
    testProperty "RemovePad then Pad == id" $ \bs ->
        let x = encodeBase64 bs
        in unsafePad64 (unsafeRemovePad64 x) === x

-- Check that padding and unpadding is consistent
testUnsafePadding64_2 :: TestTree
testUnsafePadding64_2 =
    testProperty "Pad then RemovePad == id" $ \(UnpaddedBase64 txt) ->
        unsafeRemovePad64 (unsafePad64 txt) === txt

newtype UnpaddedBase64 = UnpaddedBase64 Text
  deriving (Eq, Show)

-- Generate valid non-empty unpadded base 64
instance Arbitrary UnpaddedBase64 where
    arbitrary = do
        -- txt will be non-empty when filtering out non-base64 characters
        txt <- arbitrary `suchThat` \txt -> not (T.null $ keep64 txt)
        let correctTxt = keep64 txt
        finalTxt <-
            -- base64 always has chunks of 2-3-4 length,
            -- so add one when we end up with a chunk of 1
            if T.length correctTxt `mod` 4 /= 1
                then pure correctTxt
                else do
                    c <- elements base64set
                    pure $ c `T.cons` correctTxt
        pure $ UnpaddedBase64 finalTxt
      where
        base64set = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+"
        keep64 = T.filter (`elem` base64set)
#endif
