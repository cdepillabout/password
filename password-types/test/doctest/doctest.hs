module Main where

import Build_doctests (flags, pkgs, module_sources)
import System.Environment.Compat (unsetEnv)
import Test.DocTest (doctest)

main :: IO ()
main = do
  unsetEnv "GHC_ENVIRONMENT"
  doctest args
  where
    args = flags ++ pkgs ++ module_sources
