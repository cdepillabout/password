# password-cli

[![Build Status](https://github.com/cdepillabout/password/workflows/password/badge.svg)](http://github.com/cdepillabout/password)
[![Hackage](https://img.shields.io/hackage/v/password-cli.svg)](https://hackage.haskell.org/package/password-cli)
[![Stackage LTS](http://stackage.org/package/password-cli/badge/lts)](http://stackage.org/lts/package/password-cli)
[![Stackage Nightly](http://stackage.org/package/password-cli/badge/nightly)](http://stackage.org/nightly/package/password-cli)
[![BSD3 license](https://img.shields.io/badge/license-BSD3-blue.svg)](./LICENSE)

This package provides a simple CLI for [password](https://hackage.haskell.org/package/password) package.

Pipeline usage:

```
$ password-cli check argon2 --quiet --hash $(password-cli hash argon2 --quiet)
```

Interactive mode (default):

```
$ password-cli hash argon2
$ password-cli check argon2 --hash "SOME-HASH"
```
