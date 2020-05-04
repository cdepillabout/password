# password

[![Build Status](https://secure.travis-ci.org/cdepillabout/password.svg)](http://travis-ci.org/cdepillabout/password)
[![Hackage](https://img.shields.io/hackage/v/password.svg)](https://hackage.haskell.org/package/password)
[![Stackage LTS](http://stackage.org/package/password/badge/lts)](http://stackage.org/lts/package/password)
[![Stackage Nightly](http://stackage.org/package/password/badge/nightly)](http://stackage.org/nightly/package/password)
[![BSD3 license](https://img.shields.io/badge/license-BSD3-blue.svg)](./LICENSE)

This library provides datatypes and functions for working with passwords and
password hashes in Haskell.

Currently supports the following algorithms:

* `PBKDF2`
* `bcrypt`
* `scrypt`
* `Argon2`

Also, see the [password-instances](https://hackage.haskell.org/package/password-instances)
package for instances for common typeclasses.
