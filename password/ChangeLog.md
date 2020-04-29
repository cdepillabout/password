# Changelog for password

## 2.0.0.0

-   Complete overhaul of the library to include hashing and checking
    passwords with not just `scrypt`, but also `PBKDF2`, `bcrypt` and
    `Argon2`.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   `cryptonite` is now used as a dependency, instead of the `scrypt` package.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   Done away with abbreviating password (`Pass/pass` -> `Password/password`)
    [#8](https://github.com/cdepillabout/password/pull/8)
-   Removed `unsafeShowPasswordText` and changed `unsafeShowPassword` to be
    `Password -> Text`. (Anyone who needs it to be a `String` knows where to
    find `Data.Text.unpack`)
    [#8](https://github.com/cdepillabout/password/pull/8)
-   GHC versions < 8.2 are no longer actively supported. (Tested to work for GHC 8.2.2)

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

