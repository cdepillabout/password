{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Monad (unless, void)
import qualified Data.Password.Argon2 as Argon2
import Data.Password.Bcrypt (PasswordCheck (..))
import qualified Data.Password.Bcrypt as Bcrypt
import qualified Data.Password.PBKDF2 as PBKDF2
import qualified Data.Password.Scrypt as Scrypt
import Data.Password.Types
import Data.Text (Text)
import qualified Data.Text.IO as T
import Options.Applicative
import System.Exit (exitFailure)
import System.IO (IOMode(ReadMode), stdin, withFile)

main :: IO ()
main = execParser cliOpts >>= runCmd

data Cmd
  = HashCmd HashOpts
  | CheckCmd CheckOpts
  | HelpCmd (Maybe String)

data HashOpts = HashOpts {
    password :: Either FilePath Bool,
    hashAlgorithm :: HashAlgorithm
  }

data CheckOpts = CheckOpts {
    hash :: Either FilePath Text,
    password :: Either FilePath Bool,
    checkAlgorithm :: CheckAlgorithm
  }

data HashAlgorithm
  = PBKDF2HashAlgo PBKDF2.PBKDF2Params
  | BcryptHashAlgo Int
  | ScryptHashAlgo Scrypt.ScryptParams
  | Argon2HashAlgo Argon2.Argon2Params

data CheckAlgorithm
  = PBKDF2CheckAlgo
  | BcryptCheckAlgo
  | ScryptCheckAlgo
  | Argon2CheckAlgo

cliOpts :: ParserInfo Cmd
cliOpts = info commandsParser (fullDesc <> header "password CLI usage -")
  where
    commandsParser :: Parser Cmd
    commandsParser =
      subparser
        ( command
            "hash"
            (info (HashCmd <$> hashOptsParser) (progDesc "hash password"))
            <> command
              "check"
              (info (CheckCmd <$> checkOptsParser) (progDesc "check hashed password"))
            <> command "help" (info (HelpCmd <$> optional (argument str (metavar "COMMAND")) <**> helper) (progDesc "Show command help"))
        )
        <**> helper
    hashOptsParser :: Parser HashOpts
    hashOptsParser =
      HashOpts
        <$> (   (Left <$> option str (metavar "PASSWORD-FILE" <> long "password-file"))
            <|> (Right <$> switch (short 'q' <> long "quiet")))
        <*> algorithmHashParser
    checkOptsParser :: Parser CheckOpts
    checkOptsParser =
      CheckOpts
        <$> (   (Right <$> option str (metavar "HASH" <> long "hash"))
            <|> (Left <$> option str (metavar "HASH-FILE" <> long "hash-file")))
        <*> (   (Left <$> option str (metavar "PASSWORD-FILE" <> long "password-file"))
            <|> (Right <$> switch (short 'q' <> long "quiet")))
        <*> algorithmCheckParser
    algorithmHashParser :: Parser HashAlgorithm
    algorithmHashParser =
      subparser
        ( command "argon2" (info (Argon2HashAlgo <$> algoParser argon2Def) (progDesc "Argon2"))
            <> command "bcrypt" (info (BcryptHashAlgo <$> algoParser bcryptDef) (progDesc "Bcrypt"))
            <> command "pbkdf2" (info (PBKDF2HashAlgo <$> algoParser pbkdf2Def) (progDesc "PBKDF2"))
            <> command "scrypt" (info (ScryptHashAlgo <$> algoParser scryptDef) (progDesc "Scrypt"))
        )
        <**> helper
    algorithmCheckParser :: Parser CheckAlgorithm
    algorithmCheckParser =
      subparser
        ( command "argon2" (info (pure Argon2CheckAlgo) (progDesc "Argon2"))
            <> command "bcrypt" (info (pure BcryptCheckAlgo) (progDesc "Bcrypt"))
            <> command "pbkdf2" (info (pure PBKDF2CheckAlgo) (progDesc "PBKDF2"))
            <> command "scrypt" (info (pure ScryptCheckAlgo) (progDesc "Scrypt"))
        )
        <**> helper

data AlgorithmeDef a p = AlgorithmeDef
  { algoParser :: Parser p
  , algoHash :: p -> Password -> IO (PasswordHash a)
  , algoCheck :: Password -> PasswordHash a -> PasswordCheck
  }

argon2Def :: AlgorithmeDef Argon2.Argon2 Argon2.Argon2Params
argon2Def = AlgorithmeDef
  { algoParser = pure Argon2.defaultParams
  , algoHash = Argon2.hashPasswordWithParams
  , algoCheck = Argon2.checkPassword
  }

bcryptDef :: AlgorithmeDef Bcrypt.Bcrypt Int
bcryptDef = AlgorithmeDef
  { algoParser = pure Bcrypt.defaultParams
  , algoHash = Bcrypt.hashPasswordWithParams
  , algoCheck = Bcrypt.checkPassword
  }

pbkdf2Def :: AlgorithmeDef PBKDF2.PBKDF2 PBKDF2.PBKDF2Params
pbkdf2Def = AlgorithmeDef
  { algoParser = pure PBKDF2.defaultParams
  , algoHash = PBKDF2.hashPasswordWithParams
  , algoCheck = PBKDF2.checkPassword
  }

scryptDef :: AlgorithmeDef Scrypt.Scrypt Scrypt.ScryptParams
scryptDef = AlgorithmeDef
  { algoParser = pure Scrypt.defaultParams
  , algoHash = Scrypt.hashPasswordWithParams
  , algoCheck = Scrypt.checkPassword
  }

runCmd :: Cmd -> IO ()
runCmd =
  \case
    HashCmd HashOpts {..} -> do
      pw <- getPassword password
      hash <-
            case hashAlgorithm of
                Argon2HashAlgo p -> unPasswordHash <$> algoHash argon2Def p pw
                BcryptHashAlgo p -> unPasswordHash <$> algoHash bcryptDef p pw
                PBKDF2HashAlgo p -> unPasswordHash <$> algoHash pbkdf2Def p pw
                ScryptHashAlgo p -> unPasswordHash <$> algoHash scryptDef p pw
      T.putStr hash
    CheckCmd CheckOpts {..} -> do
      pw <- getPassword password
      checked <-
            case checkAlgorithm of
                Argon2CheckAlgo -> algoCheck argon2Def pw <$> getHash hash
                BcryptCheckAlgo -> algoCheck bcryptDef pw <$> getHash hash
                PBKDF2CheckAlgo -> algoCheck pbkdf2Def pw <$> getHash hash
                ScryptCheckAlgo -> algoCheck scryptDef pw <$> getHash hash
      case checked of
        PasswordCheckSuccess ->
          T.putStrLn "Hash and password match"
        PasswordCheckFail -> do
          T.putStrLn "Hash and password do not match"
          exitFailure
    HelpCmd mCmd ->
      let args = maybe id (:) mCmd ["-h"]
       in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  where
    readLine x = withFile x ReadMode T.hGetLine
    getPassword :: Either FilePath Bool -> IO Password
    getPassword =
      \case
        Left path -> mkPassword <$> readLine path
        Right quiet -> do
          unless quiet $
            putStrLn "Enter password:"
          mkPassword <$> T.hGetLine stdin
    getHash :: Either FilePath Text -> IO (PasswordHash a)
    getHash =
      \case
        Left path -> PasswordHash <$> readLine path
        Right hash -> return $ PasswordHash hash
