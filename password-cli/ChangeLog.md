## 0.1.1.0

-   Small refactor and quality of life additions.
    Thanks to [@Vlix](https://github.com/Vlix)
    [#72](https://github.com/cdepillabout/password/pull/72)

-   Changes include:
    - More complete explanation of the CLI in the README.
    - Added more description of commands and options.
    - Added option to read literal contents of a file.
    - Hash output now adds a newline when using the CLI interactively. (on Unix)
    - Added `--version` to only output the version of the CLI.

## 0.1.0.0

-   First minimal working CLI to hash passwords and verify hashes.
    Thanks to [@blackheaven](https://github.com/blackheaven)
    [#70](https://github.com/cdepillabout/password/pull/70)

-   Functionality includes:
    - Hashing (`Argon2`, `bcrypt`, `PBKDF2`, `scrypt`) interactively,
      piped to `stdin`, or from the first line in a provided file.
    - Checking a hash (`Argon2`, `bcrypt`, `PBKDF2`, `scrypt`) that is
      provided through a CLI option, or from a provided file. The password
      can be entered interactively, piped to `stdin` or from the first
      line in a provided file.
    - Option to disable logging to stdout or stderr. `-q|--quiet`
