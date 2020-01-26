# Changelog for password

## 1.0.0.0

-   `hashPassWithSalt` has switched function arguments for better currying.
-   Removed `Read` instance from `Pass` and added `Show` instance.
-   `newSalt` is now `MonadIO m` instead of `IO`.
-   `PassCheckSucc` -> `PassCheckSuccess`
-   Added `mkPass` constructor function for `Pass` so the data constructor doesn't have to be exported.
    [#6](https://github.com/cdepillabout/password/pull/6)

## 0.1.0.1

-   Small fix to make sure the doctests build with stack.
    [#3](https://github.com/cdepillabout/password/pull/3)

## 0.1.0.0

- Initial version.

