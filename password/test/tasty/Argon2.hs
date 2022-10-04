{-# LANGUAGE OverloadedStrings #-}
module Argon2 (testArgon2) where

import Test.Tasty (TestTree, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)

import Data.Password.Argon2

import TestUtils


testArgon2 :: TestTree
testArgon2 = testGroup "Argon2"
  [ referenceTest
  , testCorrectPassword "Argon2 (hashPassword)" hashFast checkPassword extractParams fastParams
  , testIncorrectPassword "Argon2 (hashPassword) fail" hashFast checkPassword
  , testWithSalt "Argon2 (hashPasswordWithSalt)"
                 (hashPasswordWithSalt fastParams)
                 checkPassword
                 extractParams
                 fastParams
  , testWithParams "Argon2 (Argon2i)" (fastParams{ argon2Variant = Argon2i })
  , testWithParams "Argon2 (Argon2d)" (fastParams{ argon2Variant = Argon2d })
  , paddingTests
  , omittedVersionTest
  ]
  where
    testWithParams s params =
      testWithSalt s (hashPasswordWithSalt params) checkPassword extractParams params
    hashFast = hashPasswordWithParams fastParams
    fastParams =
      defaultParams{
        argon2MemoryCost = 2 ^ (8 :: Int),
        argon2TimeCost = 1
      }

paddingTests :: TestTree
paddingTests = testGroup "Padding"
    [ testCase "with padding" $
        assertBool "Bad hash" $ checkPassword pass hashWithPadding == PasswordCheckSuccess
    , testCase "without padding" $
        assertBool "Bad hash" $ checkPassword pass hashWithoutPadding == PasswordCheckSuccess
    ]

pass :: Password
pass = "foobar"

-- Hashed password ("foobar") with salt ("abcdefghijklmnop")
hashWithPadding, hashWithoutPadding :: PasswordHash Argon2
hashWithPadding    = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA==$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o="
hashWithoutPadding = PasswordHash "$argon2id$v=19$m=65536,t=2,p=1$YWJjZGVmZ2hpamtsbW5vcA$BztdyfEefG5V18ZNlztPrfZaU5duVFKZiI6dJeWht0o"

-- Very old hashes might not have version parts, so infer as version 1.0
omittedVersionTest :: TestTree
omittedVersionTest = testGroup "Version 1.0"
    [ go "version 1.0 part in hash (placebo)" "testtest" v10Hash
    , go "no version part in hash == version 1.0" "testtest" v10HashWithoutVersion
    , go "version 1.3 part in hash (reference)" "password" referenceHash
    , testCase "no version 1.3 part in hash should fail" $
        assertEqual "check passed!?" PasswordCheckFail $
            checkPassword "password" referenceHashWithoutVersion
    ]
  where
    go s p = testCase s
        . assertEqual "check failed" PasswordCheckSuccess
        . checkPassword p

-- Reference check using the Command-line Utility output example
-- from: https://github.com/P-H-C/phc-winner-argon2
referenceTest :: TestTree
referenceTest = testCase "PHC Argon2 reference" $
    assertEqual "output hash is wrong" referenceHash $
        hashPasswordWithSalt params salt pwd
  where
    salt = Salt "somesalt"
    pwd = mkPassword "password"
    params = defaultParams {
        argon2Variant = Argon2i,
        argon2Parallelism = 4,
        argon2OutputLength = 24
    }

-- Weirdly lined out to show it's exactly the same, except the 'v=' part is missing.
referenceHash, referenceHashWithoutVersion :: PasswordHash Argon2
referenceHash          = PasswordHash "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
referenceHashWithoutVersion = PasswordHash "$argon2i$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG"
v10Hash, v10HashWithoutVersion :: PasswordHash Argon2
v10Hash          = PasswordHash "$argon2i$v=16$m=65536,t=2,p=1$Kx1BEcpIg0Ey5GyXq5do2w$0qRfWHw09EdqQkSsaG57O/ou8v/E6Vc83w"
v10HashWithoutVersion = PasswordHash "$argon2i$m=65536,t=2,p=1$Kx1BEcpIg0Ey5GyXq5do2w$0qRfWHw09EdqQkSsaG57O/ou8v/E6Vc83w"
