
# password

[![Build Status](https://secure.travis-ci.org/cdepillabout/password.svg)](http://travis-ci.org/cdepillabout/password)
[![BSD3 license](https://img.shields.io/badge/license-BSD3-blue.svg)](./LICENSE)

This repo provides packages for easily working with passwords in Haskell.  This
is mainly to be used for web applications that need to receive plain-text
passwords from users, and store hashed passwords in a database.

The [password-types](./password-types) package provides canonical datatypes for
plain-text and hashed passwords. This package has minimal dependencies. It is
meant to be used as a base for any other packages that wants to use these datatypes.
The [`Data.Password`](http://hackage.haskell.org/package/password-types/docs/Data-Password.html)
module contains the base datatypes.

The [password](./password) package provides functions for working with
plain-text and hashed passwords.
Every algorithm has its own module in the form of `Data.Password.ALGORITHM`
(e.g. [`Data.Password.Bcrypt`](http://hackage.haskell.org/package/password/docs/Data-Password-Bcrypt.html))
with the functions for the hashing and checking of passwords.

The [password-instances](./password-instances) package and
[`Data.Password.Instances`](http://hackage.haskell.org/package/password-instances/docs/Data-Password-Instances.html)
module adds convenient instances for passwords, like
[`FromJSON`](http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON)
and
[`PersistField`](http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistField).

In general, if you are writing a web application and need to handle passwords,
you should use the `password` package together with `password-instances`.
