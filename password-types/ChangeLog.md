# Changelog for `password-types`

## 1.0.1.0

-   Removed `memory` dependency by implementing `constEq` in this package.
-   Exporting `constEquals` for reuse in other packages to minimize dependencies
    on `memory` or `ram`.

## 1.0.0.0

-   Split out this package from the `password` package to not saddle up
    users with a `cryptonite` dependency, when they might only want to
    use password data types.
