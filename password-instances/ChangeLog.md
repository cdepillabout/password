# Changelog for `password-instances`

## 3.0.0.0

-   The `password-instances` library now depends on the new
    `password-types` package, instead of on the `password` package.
    [#40](https://github.com/cdepillabout/password/pull/40)
    Thanks to [@Vlix](https://github.com/Vlix)
-   Small update to the README
-   Changed `PersistField` instance of `PasswordHash` to use
    `decodeUtf8'` for better handling of UTF8 decoding exceptions.
    [#43](https://github.com/cdepillabout/password/pull/43)

## 2.0.0.2

-   Fixed `homepage` links in the `.cabal` files.
    [#34](https://github.com/cdepillabout/password/pull/34)
    Thanks to [@Radicalautistt](https://github.com/Radicalautistt)

## 2.0.0.1

-   Fixed README markdown for hackage.

## 2.0.0.0

-   No longer re-exports anything from `password` to be
    more predictable and in line with other `...-instances`
    packages like `quickcheck-instances` and `vector-instances`.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   Added instances for "forbidden" type classes with custom type errors.
    [#8](https://github.com/cdepillabout/password/pull/8)
-   GHC versions < 8.2 are no longer actively supported. (Tested to work for GHC 8.2.2)

## 1.0.0.0

-   Various changes re-exported from the `password` package.
    [#6](https://github.com/cdepillabout/password/pull/6)

## 0.3.0.1

-   Small fix to make sure the doctests build with stack.
    [#3](https://github.com/cdepillabout/password/pull/3)

## 0.3.0.0

-   Added instance for `PersistFieldSql` for `PassHash`.

## 0.2.0.0

-   Added instance for `PersistField` for `PassHash`.

## 0.1.0.0

-   Initial version.
