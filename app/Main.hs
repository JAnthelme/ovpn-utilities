{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Main where

import Data.Attoparsec.ByteString.Char8 (Parser)
import qualified Data.Attoparsec.ByteString.Char8 as A (parseOnly, manyTill, anyChar, string)
import qualified Data.ByteString.Char8 as S (pack)
import System.FilePath.Posix ((-<.>))
import Data.List (uncons)
import Data.Maybe (fromMaybe)

import System.Console.GetOpt
import System.Environment
import System.Exit

import System.IO (stderr, hPutStrLn)
import Control.Monad (when)
import Data.List (nub)

-----------------------
-- arguments management
-----------------------

data Flag
        = Rename String         -- -r
        | Version2              -- --version
        | Verbose2              -- --verbose
        | Help2                 -- --help
        deriving (Eq,Ord,Show)

-----------------------
-- vpn file params
-----------------------

data Params = Params
               { prms_tag :: (String, String)
               , prms_sta :: String
               , prms_end :: String
               }
def = Params { prms_tag = ("<cert>", "</cert>")
             , prms_sta = "-----BEGIN CERTIFICATE-----"
             , prms_end = "-----END CERTIFICATE-----"
             }

ca_prms   = def {prms_tag = ("<ca>", "</ca>")}
cert_prms = def
key_prms  = def {prms_tag = ("<key>", "</key>")
            , prms_sta = "-----BEGIN RSA PRIVATE KEY-----"
            , prms_end = "-----END RSA PRIVATE KEY-----"
            }

-----------------------
-- main
-----------------------

main :: IO ()
main = do
    (args, files) <- getArgs >>= parse
    let fn  = head files -- should be safe...
        fn' = fromMaybe fn $ rename args
    content <- S.pack <$> readFile fn
    -- parse tag-delimited keys
    let ca'   = A.parseOnly (grab ca_prms) content
        cert' = A.parseOnly (grab cert_prms) content
        key'  = A.parseOnly (grab key_prms) content
    -- manage potential errors
    (errca, ca) <- case ca' of
                 Left x  -> return (True, x)
                 Right y -> return (False, y)
    (errcert, cert) <- case cert' of
                 Left x  -> return (True, x)
                 Right y -> return (False, y)
    (errkey, key) <- case key' of
                 Left x  -> return (True, x)
                 Right y -> return (False, y)

    let errmsg = foldl foldmsg "" $ zip ["ca:","cert:","key:"] 
                                        [(errca, ca)
                                        ,(errcert, cert)
                                        ,(errkey, key)]

    if errca || errcert || errkey 
      then do
        print errmsg
        exitWith (ExitFailure 1)
    else do if Verbose2 `elem` args then do
                    hPutStrLn stderr ("ca string:\n" ++ ca)
                    hPutStrLn stderr ("cert string:\n" ++ cert)
                    hPutStrLn stderr ("key string:\n" ++ key)
                    hPutStrLn stderr ("source: " ++ fn)
                    hPutStrLn stderr ("dest: " ++ fn')
                    hPutStrLn stderr ("args: " ++ show (args, files))
                    else return()
                    
            writeFile (fn' -<.> "ca") ca
            writeFile (fn' -<.> ".cert") cert
            writeFile (fn' -<.> ".key") key
    return ()

flags :: [OptDescr Flag]
flags =
   [Option ['r']     ["rename"]  (ReqArg Rename "FILE")    "rename the output file."
   ,Option []        ["version"] (NoArg Version2)  "show version number."
   ,Option ['v']     ["verbose"] (NoArg Verbose2)  "chatty ouput on stderr."
   ,Option ['h','?'] ["help"]    (NoArg Help2)     "print this help message."
   ]

parse :: [String] -> IO ([Flag], [String])
parse argv = case getOpt Permute flags argv of
    (args,fs,[]) -> do
        let files = fs -- if null fs then ["-"] else fs
        
        when (Help2 `elem` args) $ do
            hPutStrLn stderr (usageInfo header flags)
            exitWith ExitSuccess
        when (Version2 `elem` args) $ do 
            hPutStrLn stderr "Version 0.1.0"
            exitWith ExitSuccess
        when (null files) $ do 
            hPutStrLn stderr "No filename provided."
            exitWith (ExitFailure 1)
        return (nub (concatMap set args), files)
 
    (_,_,errs)      -> do
        hPutStrLn stderr (concat errs ++ usageInfo header flags)
        exitWith (ExitFailure 1)
 
    where header = "Usage: vpnfile [-rvh?] [file ...]"
          -- set Rename = [Rename, OtherOption] -- in case one option triggers another one
          set f = [f]

-- Return Just foostr if Rename foostr is present in Flag and foostr/="", Nothing otherwise
rename :: [Flag] -> Maybe String
rename flgs = let xs = map ulift $ filter test flgs in fmap fst $ uncons xs
    where test (Rename "") = False
          test (Rename _) = True
          test _ = False
          ulift (Rename x) = x
          ulift _ = ""

----------------------
-- local functions
----------------------

-- | return the string delimited tags: tag1 prms_sta RETURNEDSTRING prms_end tag2
grab :: Params -> Parser String
grab prms = do
    let (tag1,tag2) = prms_tag prms
    A.manyTill A.anyChar $ A.string $ S.pack tag1
    A.manyTill A.anyChar $ A.string $ S.pack $ prms_sta prms
    x <- A.manyTill A.anyChar $ A.string $ S.pack $ prms_end prms
    return  (prms_sta prms ++ x ++ prms_end prms)

foldmsg :: String -> (String, (Bool, String)) -> String
foldmsg = \m' (tag,(e,m)) -> if e then m' ++ "/" ++ tag ++ m else m'
