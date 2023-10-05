# Changelog for `password`

## 3.0.3.0

-  Added `bcrypt` `defaultParams` used by `hashPassword`
  Thanks to [@blackheaven](https://github.com/blackheaven)
    [#70](https://github.com/cdepillabout/password/pull/70)

## 3.0.2.2

-   Added extra documentation about `bcrypt` hashes.
    Thanks to [@Vlix](https://github.com/Vlix)
    [#69](https://github.com/cdepillabout/password/pull/69)

## 3.0.2.1

-   Add Cabal flags to control which hashing algorithms are exported. These flags are
    `argon2`, `bcrypt`, `pbkdf2`, and `scrypt`. Each flag is enabled by default -
    disabling it will elide the corresponding module from the library. This allows
    downstream packagers to disable hashing algorithms which aren't supported on
    certain platforms.
    Thanks to [@ivanbakel](https://github.com/ivanbakel)
    [#63](https://github.com/cdepillabout/password/pull/63)

## 3.0.2.0

-   Add `extractParams` on `PasswordHash`s
    Thanks to [@blackheaven](https://github.com/blackheaven)
    [#61](https://github.com/cdepillabout/password/pull/61)

## 3.0.1.0

-   Argon2 hashes without a version field are interpreted as being of version 1.0
    Thanks to [@Vlix](https://github.com/Vlix)
    [#56](https://github.com/cdepillabout/password/pull/56)

## 3.0.0.0

-   Split the main datatypes module (`Data.Password`) into a separate package: `password-types`.
    The new package just contains `Password`, `PasswordHash`, `Salt` and their helper functions/instances.
-   Adjusted entire `password` package to use the `Data.Password.Types` from this new `password-types`.
    Thanks to [@Vlix](https://github.com/Vlix)
    [#40](https://github.com/cdepillabout/password/pull/40)
-   Argon2: fixed the producing and checking of Argon2 hashes.
    The base64 padding is removed when producing hashes and when
    checking hashes it will accept hashes with or without padding.
    [#45](https://github.com/cdepillabout/password/pull/45)

## 2.1.1.0

-   Fixed `homepage` links in the `.cabal` files.
    [#34](https://github.com/cdepillabout/password/pull/34)
    Thanks to [@Radicalautistt](https://github.com/Radicalautistt)
-   Updated the `defaultPasswordPolicy` and documentation of the
    `Data.Password.Validate` module using information about research done on
    "memorized secrets" (i.e. passwords) by the NIST.
    [#31] https://github.com/cdepillabout/password/pull/31
    Thanks to [@agentultra](https://github.com/agentultra) for pointing out
    the research and starting the PR.
    [#39](https://github.com/cdepillabout/password/pull/39)
    Thanks to [@Vlix](https://github.com/Vlix) for updating the rest of the
    documentation.
-   Small spelling and other documentation fixes.

## 2.1.0.0

-   A new `Validate` module has been added to dictate policies that passwords
    should adhere to and the necessary API to verify that they do.
    [#26](https://github.com/cdepillabout/password/pull/26)
    Huge thanks to [@HirotoShioi](https://github.com/HirotoShioi) for picking
    up the task of adding this functionality and doing most of the groundwork.
    [#27](https://github.com/cdepillabout/password/pull/27)
    Thanks to [@Vlix](https://github.com/Vlix) for finishing up the API and
    documentation.

## 2.0.1.1

-   Fixed cross-module links in the haddocks.
    [#19](https://github.com/cdepillabout/password/pull/19) Thanks to
    [@TristanCacqueray](https://github.com/TristanCacqueray) for fixing this.

## 2.0.1.0

-   Switched checking hashes to using `Data.ByteArray.constEq`, instead of
    the default `(==)` method of `ByteString`. This is to make it more secure
    against timing attacks. [#16](https://github.com/cdepillabout/password/pull/16)
    Thanks to [@maralorn](https://github.com/maralorn) for bringing this up.

## 2.0.0.1

-   Fixed README markdown for hackage.

## 2.0.0.0

-   Complete overhaul of the library to include hashing and checking
    passwords with not just `scrypt`, but also `PBKDF2`, `bcrypt` and
    `Argon2`.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   `cryptonite` is now used as a dependency, instead of the `scrypt` package.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   Done away with abbreviating "password" (`Pass/pass` -> `Password/password`)
    [#8](https://github.com/cdepillabout/password/pull/8)
-   Removed `unsafeShowPasswordText` and changed `unsafeShowPassword` to be
    `Password -> Text`. (Anyone who needs it to be a `String` knows where to
    find `Data.Text.unpack`)
    [#8](https://github.com/cdepillabout/password/pull/8)
-   GHC versions < 8.2 are no longer actively supported.
    (Tested to work for GHC 8.2.2)

## 1.0.0.0

-   `hashPassWithSalt` has switched function arguments for better currying.
    [#6](https://github.com/cdepillabout/password/pull/6)
    Although be warned that multiple passwords
    [should not be hashed with the same salt](https://github.com/cdepillabout/password/pull/6#discussion_r370455681).
-   Removed `Read` instance from `Pass` and added `Show` instance.
    [#6](https://github.com/cdepillabout/password/pull/6)
    See [#5](https://github.com/cdepillabout/password/issues/5#issuecomment-576958351)
    for justification of this.
-   `newSalt` is now `MonadIO m` instead of `IO`.
    [#6](https://github.com/cdepillabout/password/pull/6)
-   `PassCheckSucc` has been renamed to `PassCheckSuccess`.
    [#6](https://github.com/cdepillabout/password/pull/6)
-   Hide data constructor from `Pass` and add the `mkPass` function to construct a `Pass`.
    [#6](https://github.com/cdepillabout/password/pull/6)
-   Thanks to Felix Paulusma ([@Vlix](https://github.com/Vlix)) for the above
    changes!

## 0.1.0.1

-   Small fix to make sure the doctests build with stack.
    [#3](https://github.com/cdepillabout/password/pull/3)

## 0.1.0.0

- Initial version.
