{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE RecordWildCards #-}

module Main (main) where

import Control.Exception (bracket_, evaluate)
import Control.Monad (unless, void, (<=<))
import qualified Data.ByteString.Char8 as B (readFile)
import Data.Password.Bcrypt (PasswordCheck (..))
import Data.Password.Types (Password, mkPassword)
import Data.Text as T (Text, strip)
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as T
import Options.Applicative
import System.Exit (exitFailure)
import System.IO (IOMode (ReadMode), hIsTerminalDevice, hSetEcho, stderr, stdin, stdout, withFile)

import Options

main :: IO ()
main =
  customExecParser (prefs showHelpOnEmpty) cliOpts >>= runCmd

runCmd :: CLIOptions -> IO ()
runCmd CLIOptions{..} =
    case cmd of
        HashCmd opts -> runHashCmd quiet opts
        CheckCmd opts -> runCheckCmd quiet opts
        HelpCmd cmds -> void $ runHelpCmd cmds

runHashCmd :: Bool -> HashOpts -> IO ()
runHashCmd quiet HashOpts {..} = do
    pw <- getPassword quiet hashPassword
    hash <- hashWithAlgorithm pw hashAlgorithm
    b <- hIsTerminalDevice stdin
    let output =
            if b then T.putStrLn else T.putStr
    output hash

runCheckCmd :: Bool -> CheckOpts -> IO ()
runCheckCmd quiet CheckOpts {..} = do
    pw <- getPassword quiet checkPassword
    hashedPW <- getHash hash
    case checkWithAlgorithm pw hashedPW checkAlgorithm of
        PasswordCheckSuccess ->
            qLog stdout "Password matches provided hash"
        PasswordCheckFail -> do
            qLog stderr "Password does not match provided hash"
            exitFailure
  where
    qLog h = unless quiet . T.hPutStrLn h

runHelpCmd :: [String] -> IO CLIOptions
runHelpCmd cmds =
  let args = cmds ++ ["-h"]
   in handleParseResult $ execParserPure defaultPrefs cliOpts args

getPassword :: Bool -> Maybe FromFileOptions -> IO Password
getPassword quiet = \case
    Just FromFileOptions{..} ->
        mkPassword <$> readLine parseLiteralContents fromFile
    Nothing -> do
        unless quiet $
            putStrLn "Enter password:"
        bracket_
            (hSetEcho stdin False)
            (hSetEcho stdin True)
            (mkPassword <$> T.hGetLine stdin)

getHash :: Either FromFileOptions Text -> IO Text
getHash = \case
    Right hash -> pure hash
    Left FromFileOptions{..} -> readLine parseLiteralContents fromFile

readLine :: Bool -> FilePath -> IO Text
readLine literal x
    | literal = readFullFile x
    -- When not given the 'parseLiteralContents' flag, we want to be
    -- lenient, and ignore white space around any hash, since those
    -- will never be part of any hash, and probably also not a password.
    | otherwise = T.strip <$> withFile x ReadMode T.hGetLine

-- | Copied from newest 'text-2.1' 'Data.Text.IO.Utf8' module
readFullFile :: FilePath -> IO Text
readFullFile = evaluate . TE.decodeUtf8 <=< B.readFile
