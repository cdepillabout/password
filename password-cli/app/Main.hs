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
import System.IO (stdin)

main :: IO ()
main = execParser cliOpts >>= runCmd

data Cmd
  = Argon2Cmd GenericAlgoSubCmd
  | BcryptCmd GenericAlgoSubCmd
  | PBKDF2Cmd GenericAlgoSubCmd
  | ScryptCmd GenericAlgoSubCmd
  | HelpCmd (Maybe String)

data GenericAlgoSubCmd
  = HashGenericAlgoSubCmd HashGenericAlgoSubCmdOpts
  | CheckGenericAlgoSubCmd CheckGenericAlgoSubCmdOpts

newtype HashGenericAlgoSubCmdOpts = HashGenericAlgoSubCmdOpts
  { quiet :: Bool
  }

data CheckGenericAlgoSubCmdOpts = CheckGenericAlgoSubCmdOpts
  { quiet :: Bool,
    hash :: Text
  }

cliOpts :: ParserInfo Cmd
cliOpts = info commandsParser (fullDesc <> header "password CLI usage")
  where
    commandsParser :: Parser Cmd
    commandsParser =
      subparser
        ( command "argon2" (info (Argon2Cmd <$> genericAlgoSubCmdParser) (progDesc "Argon2 operations"))
            <> command "bcrypt" (info (BcryptCmd <$> genericAlgoSubCmdParser) (progDesc "Bcrypt operations"))
            <> command "pbkdf2" (info (PBKDF2Cmd <$> genericAlgoSubCmdParser) (progDesc "Pbkdf2 operations"))
            <> command "scrypt" (info (ScryptCmd <$> genericAlgoSubCmdParser) (progDesc "Scrypt operations"))
            <> command "help" (info (HelpCmd <$> optional (argument str (metavar "COMMAND")) <**> helper) (progDesc "Show command help"))
        )
        <**> helper
    genericAlgoSubCmdParser :: Parser GenericAlgoSubCmd
    genericAlgoSubCmdParser =
      subparser
        ( command
            "hash"
            (info (HashGenericAlgoSubCmd <$> hashGenericAlgoSubCmdOptsParser) (progDesc "hash password (via STDIN)"))
            <> command
              "check"
              (info (CheckGenericAlgoSubCmd <$> checkGenericAlgoSubCmdOptsParser) (progDesc "check hashed password (via STDIN)"))
        )
        <**> helper
    hashGenericAlgoSubCmdOptsParser :: Parser HashGenericAlgoSubCmdOpts
    hashGenericAlgoSubCmdOptsParser =
      HashGenericAlgoSubCmdOpts
        <$> switch (short 'q' <> long "quiet")
    checkGenericAlgoSubCmdOptsParser :: Parser CheckGenericAlgoSubCmdOpts
    checkGenericAlgoSubCmdOptsParser =
      CheckGenericAlgoSubCmdOpts
        <$> switch (short 'q' <> long "quiet")
        <*> option str (metavar "HASH" <> long "hash")

runCmd :: Cmd -> IO ()
runCmd =
  \case
    Argon2Cmd subCmd -> runGenericAlgoSubCmd Argon2.hashPassword Argon2.checkPassword subCmd
    BcryptCmd subCmd -> runGenericAlgoSubCmd Bcrypt.hashPassword Bcrypt.checkPassword subCmd
    PBKDF2Cmd subCmd -> runGenericAlgoSubCmd PBKDF2.hashPassword PBKDF2.checkPassword subCmd
    ScryptCmd subCmd -> runGenericAlgoSubCmd Scrypt.hashPassword Scrypt.checkPassword subCmd
    HelpCmd mCmd ->
      let args = maybe id (:) mCmd ["-h"]
       in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args
  where
    runGenericAlgoSubCmd ::
      (Password -> IO (PasswordHash a)) ->
      (Password -> PasswordHash a -> PasswordCheck) ->
      GenericAlgoSubCmd ->
      IO ()
    runGenericAlgoSubCmd mkHash mkCheck =
      \case
        HashGenericAlgoSubCmd HashGenericAlgoSubCmdOpts {..} -> do
          unless quiet $
            putStrLn "Enter password:"
          password <- mkPassword <$> T.hGetLine stdin
          hash <- mkHash password
          T.putStr $ unPasswordHash hash
        CheckGenericAlgoSubCmd CheckGenericAlgoSubCmdOpts {..} -> do
          unless quiet $
            putStrLn "Enter password:"
          password <- mkPassword <$> T.hGetLine stdin
          case mkCheck password (PasswordHash hash) of
            PasswordCheckSuccess ->
              T.putStrLn "Hash and password match"
            PasswordCheckFail -> do
              T.putStrLn "Hash and password do not match"
              exitFailure
