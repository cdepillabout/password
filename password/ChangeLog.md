# Changelog for password

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

