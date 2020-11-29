module TestPolicy where

import Data.Password.Validate (
    PasswordPolicy (..),
    defaultPasswordPolicy,
 )

-- This is used for the TH test just so it would be obvious if
-- any numbers suddenly switched between fields.
-- (e.g. uppercaseChars and lowercaseChars suddenly switch places
-- after going through validatePasswordPolicyTH)
testPolicy :: PasswordPolicy
testPolicy =
    defaultPasswordPolicy
        { minimumLength = 8
        , maximumLength = 64
        , uppercaseChars = 3
        , lowercaseChars = 4
        , specialChars = 5
        , digitChars = 6
        }
