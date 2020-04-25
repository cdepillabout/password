# Changelog for password-instances

## 2.0.0.0

-   No longer re-exports anything from `password` to be
    more predictable and in line with other `...-instances`
    packages like `quickcheck-instances` and `vector-instances`.

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

