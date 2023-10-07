{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Exception (bracket_)
import Control.Monad (unless, void)
import Data.Version (showVersion)
import qualified Data.Password.Argon2 as Argon2
import Data.Password.Bcrypt (PasswordCheck (..))
import qualified Data.Password.Bcrypt as Bcrypt
import qualified Data.Password.PBKDF2 as PBKDF2
import qualified Data.Password.Scrypt as Scrypt
import Data.Password.Types
import Data.Text (Text)
import qualified Data.Text.IO as T
import Options.Applicative
import Paths_password_cli (version)
import System.Exit (exitFailure)
import System.IO (IOMode(ReadMode), hSetEcho, stdin, stderr, withFile)

main :: IO ()
main =
  customExecParser (prefs showHelpOnEmpty) cliOpts >>= runCmd

data Cmd
  = HashCmd HashOpts
  | CheckCmd CheckOpts
  | HelpCmd (Maybe String)

data HashOpts = HashOpts {
    quiet :: Bool,
    password :: Maybe FilePath,
    hashAlgorithm :: HashAlgorithm
  }

data CheckOpts = CheckOpts {
    hash :: Either FilePath Text,
    quiet :: Bool,
    password :: Maybe FilePath,
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
cliOpts = info commandsParser (fullDesc <> header ("Password CLI " <> showVersion version))
  where
    commandsParser :: Parser Cmd
    commandsParser =
      hsubparser
        ( command
            "hash"
            (info (HashCmd <$> hashOptsParser) (progDesc "hash password"))
            <> command
              "check"
              (info (CheckCmd <$> checkOptsParser) (progDesc "check hashed password"))
            <> command "help" (info (HelpCmd <$> optional (argument str (metavar "COMMAND")) <**> helper) (progDesc "Show command help"))
        )
    hashOptsParser :: Parser HashOpts
    hashOptsParser =
      HashOpts
        <$> switch (short 'q' <> long "quiet")
        <*> optional (option str (metavar "PASSWORD-FILE" <> long "password-file"))
        <*> algorithmHashParser
    checkOptsParser :: Parser CheckOpts
    checkOptsParser =
      CheckOpts
        <$> (   (Right <$> option str (metavar "HASH" <> long "hash"))
            <|> (Left <$> option str (metavar "HASH-FILE" <> long "hash-file")))
        <*> switch (short 'q' <> long "quiet")
        <*> optional (option str (metavar "PASSWORD-FILE" <> long "password-file"))
        <*> algorithmCheckParser
    algorithmHashParser :: Parser HashAlgorithm
    algorithmHashParser =
      hsubparser
        ( command "argon2" (info (Argon2HashAlgo <$> algoParser argon2Def) (progDesc "Argon2"))
            <> command "bcrypt" (info (BcryptHashAlgo <$> algoParser bcryptDef) (progDesc "Bcrypt"))
            <> command "pbkdf2" (info (PBKDF2HashAlgo <$> algoParser pbkdf2Def) (progDesc "PBKDF2"))
            <> command "scrypt" (info (ScryptHashAlgo <$> algoParser scryptDef) (progDesc "Scrypt"))
        )
    algorithmCheckParser :: Parser CheckAlgorithm
    algorithmCheckParser =
      hsubparser
        ( command "argon2" (info (pure Argon2CheckAlgo) (progDesc "Argon2"))
            <> command "bcrypt" (info (pure BcryptCheckAlgo) (progDesc "Bcrypt"))
            <> command "pbkdf2" (info (pure PBKDF2CheckAlgo) (progDesc "PBKDF2"))
            <> command "scrypt" (info (pure ScryptCheckAlgo) (progDesc "Scrypt"))
        )

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
    HashCmd opts -> runHashCmd opts
    CheckCmd opts -> runCheckCmd opts
    HelpCmd mCmd -> runHelpCmd mCmd

runHashCmd :: HashOpts -> IO ()
runHashCmd HashOpts {..} = do
  pw <- getPassword quiet password
  hash <-
        case hashAlgorithm of
            Argon2HashAlgo p -> unPasswordHash <$> algoHash argon2Def p pw
            BcryptHashAlgo p -> unPasswordHash <$> algoHash bcryptDef p pw
            PBKDF2HashAlgo p -> unPasswordHash <$> algoHash pbkdf2Def p pw
            ScryptHashAlgo p -> unPasswordHash <$> algoHash scryptDef p pw
  T.putStr hash

runCheckCmd :: CheckOpts -> IO ()
runCheckCmd CheckOpts {..} = do
  pw <- getPassword quiet password
  checked <-
        case checkAlgorithm of
            Argon2CheckAlgo -> algoCheck argon2Def pw <$> getHash hash
            BcryptCheckAlgo -> algoCheck bcryptDef pw <$> getHash hash
            PBKDF2CheckAlgo -> algoCheck pbkdf2Def pw <$> getHash hash
            ScryptCheckAlgo -> algoCheck scryptDef pw <$> getHash hash
  case checked of
    PasswordCheckSuccess ->
      unless quiet $
        T.putStrLn "Hash and password match"
    PasswordCheckFail -> do
      unless quiet $
        T.hPutStrLn stderr "Hash and password do not match"
      exitFailure

runHelpCmd :: Maybe String -> IO ()
runHelpCmd mCmd =
  let args = maybe id (:) mCmd ["-h"]
   in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args

getPassword :: Bool -> Maybe FilePath -> IO Password
getPassword quiet =
  \case
    Just path ->
      mkPassword <$> readLine path
    Nothing -> do
      unless quiet $
        putStrLn "Enter password:"
      bracket_
        (hSetEcho stdin False)
        (hSetEcho stdin True)
        (mkPassword <$> T.hGetLine stdin)

getHash :: Either FilePath Text -> IO (PasswordHash a)
getHash =
  \case
    Left path -> PasswordHash <$> readLine path
    Right hash -> return $ PasswordHash hash

readLine :: FilePath -> IO Text
readLine x = withFile x ReadMode T.hGetLine
