# `password-cli`

[![Build Status](https://github.com/cdepillabout/password/workflows/password/badge.svg)](http://github.com/cdepillabout/password)
[![Hackage](https://img.shields.io/hackage/v/password-cli.svg)](https://hackage.haskell.org/package/password-cli)
[![Stackage LTS](http://stackage.org/package/password-cli/badge/lts)](http://stackage.org/lts/package/password-cli)
[![Stackage Nightly](http://stackage.org/package/password-cli/badge/nightly)](http://stackage.org/nightly/package/password-cli)
[![BSD3 license](https://img.shields.io/badge/license-BSD3-blue.svg)](./LICENSE)

This package provides a simple CLI for the [`password`](https://hackage.haskell.org/package/password) package.
As such it supports all the algorithms that the [`password`](https://hackage.haskell.org/package/password)
package supports, which at the time of writing are `Argon2`, `brypt`, `PBKDF2` and `scrypt`.

At the moment, the default settings are used for each algorithm, but this will probably become configurable in
a later version of the CLI.

## Example usage

The following sections give examples of how the CLI can be used.

### Hashing a password interactively

Hashing a password interactively is as easy as
```console
$ password-cli hash bcrypt
Enter password:
```
where the input is then hidden and the hash is printed to the screen, resulting in
```console
$ password-cli hash bcrypt
Enter password:
$2b$10$JuNbIWqVQD2EldT481zEEuaVKROrYhsHXLjM/Tx3e7ahJQxVw7N4y
```

### Hashing a password with pipes

When piping in the password from a file or other program:
```console
$ cat password.txt | password-cli hash pbkdf2
Enter password:
sha512:25000:8ZJ1T55Y0sPRwltXNe/2fA==:aA0BT1WlTg+t2pSr8E6+l2zJW88rmUiDlKeohSOnzS0nLOumDSyK0FfsiNJBvWvWVkB2r6IMxRqelk4LZR33ow==
```
You'll notice the output has no newline, so you can easily pipe the resulting
hash into a file or other program. When piping the result to a file, you'll
probably want to use `--quiet` or `-q` to make sure the `Enter password:` prompt
isn't also saved to the file.
```console
$ cat password.txt | password-cli hash pbkdf2 --quiet > password.hash
$ cat password.hash
sha512:25000:iFYCOgfOgMPp0NuPXhyucw==:XUMDNnqZo2LH08CIZr+1nbTke3N6pE95FcbZA+4A1Ng4dWHnnl4SMUTn3KXFtB0uZRrEhArLatLAH1Oo8brcVw==
```
When piping in the password, the first line of the file (i.e. up to the first newline)
is read and taken as the password. This is also the case if the password is provided
from a file, though you can set the `--literal-contents` flag to use the entire literal
file contents as the password.

### Hashing a password from a file

Instead of piping in the contents of a file, you can also just provide the path
to the file.
```console
$ password-cli hash scrypt --password-file password.txt
14|8|1|mdSECCGuEMf7GQOp9EX5EYLMW9Jwe6Dma7fwbxuNwvs=|KSh5jxOEiQPMjfng2D05/G1baiF2LyluWgg3Cfzh5arJUF3K7irRIBXoKAT/xCO11oPmsgDD7TT6l6FQth9f4g==
```
Here you don't have to pass in the `--quiet` option, since the password is already provided
so the CLI doesn't print `Enter password:` to the screen.

### Verifying a password hash

Just like when hashing a password, you can input the password manually, through pipes, or
by providing a `--password-file`.
```console
$ # Interactively check password
$ password-cli check argon2 --hash "SOME-HASH"
Enter password:
Password matches provided hash
$ echo $?
0
```
If the provided hash doesn't match the password, `Password does not match provided hash`
will be shown and the exit code will be `1` to indicate a failed match.
```console
$ # Pipe in the password.
$ cat password.txt | password-cli check argon2 --hash "SOME-HASH" --quiet
$ echo $?
0
$ # Give the WRONG password file.
$ password-cli check argon2 --hash "SOME-HASH" --password-file password.txt.wrong --quiet
$ echo $?
1
```

You can also provide the hash from file contents by providing the path to the `--hash-file`
option. Just like the default of the `--password-file` option, this will only read up to the
first newline.
```console
$ password-cli check argon2 --hash-file password.hash
```
