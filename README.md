
# password

This repo provides packages for easily working with passwords in Haskell.  This
is mainly to be used for web applications that need to receive plain-text
passwords from users, and store hashed passwords in a database.

The [password](./password) package and
[`Data.Password`](http://hackage.haskell.org/package/password/docs/Data-Password.html)
module provides datatypes and functions for working with plain-text and hashed
passwords.

The [password-instances](./password-instances) package and
[`Data.Password.Instances`](http://hackage.haskell.org/package/password-instances/docs/Data-Password-Instances.html)
module re-exports the API from `Data.Password`, as well as adding convenient
instances for passwords, like
[`FromJSON`](http://hackage.haskell.org/package/aeson/docs/Data-Aeson.html#t:FromJSON)
and
[`PersistField`](http://hackage.haskell.org/package/persistent/docs/Database-Persist-Class.html#t:PersistEntity).

In general, if you are writing a web application and need to handle passwords,
you should use the `password-instances` package.
