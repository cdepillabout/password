{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Options where

import qualified Data.Password.Argon2 as Argon2
import Data.Password.Bcrypt (PasswordCheck (..))
import qualified Data.Password.Bcrypt as Bcrypt
import qualified Data.Password.PBKDF2 as PBKDF2
import qualified Data.Password.Scrypt as Scrypt
import Data.Password.Types
import Data.Text (Text)
import Data.Version (showVersion)
import Options.Applicative
import Paths_password_cli (version)

data CLIOptions = CLIOptions
    { quiet :: Bool
    -- ^ Prevent any logging to stdout or stderr.
    , cmd :: Cmd
    -- ^ What command
    }

data Cmd
    = HashCmd HashOpts
    | CheckCmd CheckOpts
    | HelpCmd [String]

data FromFileOptions = FromFileOptions
    { fromFile :: FilePath
    , parseLiteralContents :: Bool
    }

data HashOpts = HashOpts
    { hashPassword :: Maybe FromFileOptions
    , hashAlgorithm :: HashAlgorithm
    }

data CheckOpts = CheckOpts
    { hash :: Either FromFileOptions Text
    , checkPassword :: Maybe FromFileOptions
    , checkAlgorithm :: CheckAlgorithm
    }

data HashAlgorithm
    = PBKDF2HashAlgo PBKDF2.PBKDF2Params
    | BcryptHashAlgo Int
    | ScryptHashAlgo Scrypt.ScryptParams
    | Argon2HashAlgo Argon2.Argon2Params

hashWithAlgorithm :: Password -> HashAlgorithm -> IO Text
hashWithAlgorithm pw = \case
    Argon2HashAlgo p ->
        unPasswordHash <$> Argon2.hashPasswordWithParams p pw
    BcryptHashAlgo p ->
        unPasswordHash <$> Bcrypt.hashPasswordWithParams p pw
    PBKDF2HashAlgo p ->
        unPasswordHash <$> PBKDF2.hashPasswordWithParams p pw
    ScryptHashAlgo p ->
        unPasswordHash <$> Scrypt.hashPasswordWithParams p pw

data CheckAlgorithm
    = PBKDF2CheckAlgo
    | BcryptCheckAlgo
    | ScryptCheckAlgo
    | Argon2CheckAlgo

checkWithAlgorithm :: Password -> Text -> CheckAlgorithm -> PasswordCheck
checkWithAlgorithm pw hashT = \case
    Argon2CheckAlgo -> Argon2.checkPassword pw hash
    BcryptCheckAlgo -> Bcrypt.checkPassword pw hash
    PBKDF2CheckAlgo -> PBKDF2.checkPassword pw hash
    ScryptCheckAlgo -> Scrypt.checkPassword pw hash
  where
    hash :: PasswordHash a
    hash = PasswordHash hashT

cliOpts :: ParserInfo CLIOptions
cliOpts =
    info cliOptsParser infoMods
  where
    v = showVersion version
    infoMods =
        fullDesc
            <> header ("Password CLI " <> v)
            <> progDesc
                "A command line interface to hash and check passwords in the terminal."
    cliOptsParser =
        CLIOptions
            <$> switch (short 'q' <> long "quiet" <> help "Suppress logging to stdout and stderr")
            <*> commandsParser
            <**> simpleVersioner v
            <**> helper

commandsParser :: Parser Cmd
commandsParser =
    hsubparser $
        command "hash" hashCmd
            <> command "check" checkCmd
            <> command "help" helpCmd
  where
    hashCmd =
        info (HashCmd <$> hashOptsParser) $
            progDesc
                "Hash a password from a file, or via stdin. Outputs to stdout.\
                \ (Will add a newline at the end when used interactively on Unix)"
    checkCmd =
        info (CheckCmd <$> checkOptsParser) $
            progDesc
                "Verify a hashed password from file or stdin. Returns exit code 0\
                \ when successful, and exit code 1 when the password did not match."
    helpCmd =
        info (HelpCmd <$> many (argument str (metavar "COMMAND"))) $
            progDesc "Show help text for the given command(s)"

hashOptsParser :: Parser HashOpts
hashOptsParser =
    HashOpts <$> passwordFileOption <*> hashParser

checkOptsParser :: Parser CheckOpts
checkOptsParser =
    CheckOpts <$> hashOption <*> passwordFileOption <*> checkParser
  where
    hashOption =
        Right <$> strOption (metavar "HASH" <> long "hash" <> help hashOptionMsg)
            <|> Left <$> hashFileOption
    hashOptionMsg = "Provide the hash as an option."

fromFileOption :: Parser FilePath -> Parser FromFileOptions
fromFileOption fileOption =
    FromFileOptions <$> fileOption <*> literalParseSwitch
  where
    literalParseSwitch =
        switch $ long "literal-contents" <> help helpMsg
    helpMsg =
        "Hash all contents of the file. (by default only reads first line)"

passwordFileOption :: Parser (Maybe FromFileOptions)
passwordFileOption =
    optional . fromFileOption $
        strOption (metavar "FILE" <> long "password-file" <> help "Hash password from file contents")


hashFileOption :: Parser FromFileOptions
hashFileOption =
    fromFileOption $
        strOption (metavar "FILE" <> long "hash-file" <> help "Use hash from file contents")


data AlgoParsers a =
    AlgoParsers
        { argon2Parser :: Parser a
        , bcryptParser :: Parser a
        , pbkdf2Parser :: Parser a
        , scryptParser :: Parser a
        , commandDesc :: String -> String
        }

algorithmParser :: AlgoParsers a -> Parser a
algorithmParser AlgoParsers{..} =
    hsubparser
        ( commandGroup "Available algorithms:"
            <> command "argon2" (info argon2Parser (progDesc $ commandDesc "Argon2"))
            <> command "bcrypt" (info bcryptParser (progDesc $ commandDesc "bcrypt"))
            <> command "pbkdf2" (info pbkdf2Parser (progDesc $ commandDesc "PBKDF2"))
            <> command "scrypt" (info scryptParser (progDesc $ commandDesc "scrypt"))
        )

hashParser :: Parser HashAlgorithm
hashParser =
    algorithmParser
        AlgoParsers
            { argon2Parser = pure $ Argon2HashAlgo Argon2.defaultParams
            , bcryptParser = pure $ BcryptHashAlgo Bcrypt.defaultParams
            , pbkdf2Parser = pure $ PBKDF2HashAlgo PBKDF2.defaultParams
            , scryptParser = pure $ ScryptHashAlgo Scrypt.defaultParams
            , commandDesc = ("Hash a password using " <>)
            }

checkParser :: Parser CheckAlgorithm
checkParser =
    algorithmParser
        AlgoParsers
            { argon2Parser = pure Argon2CheckAlgo
            , bcryptParser = pure BcryptCheckAlgo
            , pbkdf2Parser = pure PBKDF2CheckAlgo
            , scryptParser = pure ScryptCheckAlgo
            , commandDesc = \algo -> "Check a " <> algo <> " hash"
            }
