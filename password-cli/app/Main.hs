{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Control.Monad (join, void)
import qualified Data.Password.Argon2 as Argon2
import Data.Password.Bcrypt (PasswordCheck (..))
import qualified Data.Password.Bcrypt as Bcrypt
import qualified Data.Password.PBKDF2 as PBKDF2
import qualified Data.Password.Scrypt as Scrypt
import Data.Password.Types
import qualified Data.Text.IO as T
import Options.Applicative
import System.Exit (exitFailure)
import System.IO (stdin)

main :: IO ()
main = join $ execParser cliOpts

cliOpts :: ParserInfo (IO ())
cliOpts = info (commandsParser <**> helper) (fullDesc <> header "password CLI usage")
  where
    commandsParser :: Parser (IO ())
    commandsParser =
      subparser
        ( command "argon2" (info commandArgon2 (progDesc "Argon2 operations"))
            <> command "bcrypt" (info commandBcrypt (progDesc "Bcrypt operations"))
            <> command "pbkdf2" (info commandPBKDF2 (progDesc "Pbkdf2 operations"))
            <> command "scrypt" (info commandScrypt (progDesc "Scrypt operations"))
            <> command "help" (info commandHelp (progDesc "Show command help"))
        )

commandHelp :: Parser (IO ())
commandHelp =
  go
    <$> optional (argument str (metavar "COMMAND"))
    <**> helper
  where
    go mCmd =
      let args = maybe id (:) mCmd ["-h"]
       in void $ handleParseResult $ execParserPure defaultPrefs cliOpts args

commandArgon2 :: Parser (IO ())
commandArgon2 =
  subparser
    ( command
        "hash"
        ( info
            (pure commandHash)
            (progDesc "hash password (via STDIN)")
        )
        <> command
          "check"
          ( info
              (commandCheck <$> option str (metavar "HASH" <> long "hash") <**> helper)
              (progDesc "check hashed password (via STDIN)")
          )
    )
    <**> helper
  where
    commandHash = runHash Argon2.hashPassword
    commandCheck hash = runCheck $ \password -> Argon2.checkPassword password $ PasswordHash hash

commandBcrypt :: Parser (IO ())
commandBcrypt =
  subparser
    ( command
        "hash"
        ( info
            (pure commandHash)
            (progDesc "hash password (via STDIN)")
        )
        <> command
          "check"
          ( info
              (commandCheck <$> option str (metavar "HASH" <> long "hash") <**> helper)
              (progDesc "check hashed password (via STDIN)")
          )
    )
    <**> helper
  where
    commandHash = runHash Bcrypt.hashPassword
    commandCheck hash = runCheck $ \password -> Bcrypt.checkPassword password $ PasswordHash hash

commandPBKDF2 :: Parser (IO ())
commandPBKDF2 =
  subparser
    ( command
        "hash"
        ( info
            (pure commandHash)
            (progDesc "hash password (via STDIN)")
        )
        <> command
          "check"
          ( info
              (commandCheck <$> option str (metavar "HASH" <> long "hash") <**> helper)
              (progDesc "check hashed password (via STDIN)")
          )
    )
    <**> helper
  where
    commandHash = runHash PBKDF2.hashPassword
    commandCheck hash = runCheck $ \password -> PBKDF2.checkPassword password $ PasswordHash hash

commandScrypt :: Parser (IO ())
commandScrypt =
  subparser
    ( command
        "hash"
        ( info
            (pure commandHash)
            (progDesc "hash password (via STDIN)")
        )
        <> command
          "check"
          ( info
              (commandCheck <$> option str (metavar "HASH" <> long "hash") <**> helper)
              (progDesc "check hashed password (via STDIN)")
          )
    )
    <**> helper
  where
    commandHash = runHash Scrypt.hashPassword
    commandCheck hash = runCheck $ \password -> Scrypt.checkPassword password $ PasswordHash hash

runHash :: (Password -> IO (PasswordHash a)) -> IO ()
runHash f = do
  password <- mkPassword <$> T.hGetLine stdin
  hash <- f password
  T.putStr $ unPasswordHash hash

runCheck :: (Password -> PasswordCheck) -> IO ()
runCheck f = do
  password <- mkPassword <$> T.hGetLine stdin
  case f password of
    PasswordCheckSuccess ->
      T.putStrLn "Hash and password match"
    PasswordCheckFail -> do
      T.putStrLn "Hash and password do not match"
      exitFailure
