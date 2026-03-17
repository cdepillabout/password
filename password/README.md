# password

[![Build Status](https://github.com/cdepillabout/password/workflows/password/badge.svg)](http://github.com/cdepillabout/password)
[![Hackage](https://img.shields.io/hackage/v/password.svg)](https://hackage.haskell.org/package/password)
[![Stackage LTS](http://stackage.org/package/password/badge/lts)](http://stackage.org/lts/package/password)
[![Stackage Nightly](http://stackage.org/package/password/badge/nightly)](http://stackage.org/nightly/package/password)
[![BSD3 license](https://img.shields.io/badge/license-BSD3-blue.svg)](./LICENSE)

This library provides functions for working with passwords and password hashes in Haskell.

It currently supports the following algorithms:

* `PBKDF2`
* `bcrypt`
* `scrypt`
* `Argon2`

Also, see the [password-instances](https://hackage.haskell.org/package/password-instances)
package for instances for common typeclasses.

To quickly test and use `password`, you can use [password-cli](https://github.com/cdepillabout/password/tree/master/password-cli).
