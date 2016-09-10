{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Main where

import Data.Attoparsec.ByteString.Char8 (Parser)
import qualified Data.Attoparsec.ByteString.Char8 as A (parseOnly, manyTill, anyChar, string, endOfLine, eitherP, endOfInput, sepBy1, many1, digit, char)
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as S (pack)

import Data.List (uncons, intersperse, isPrefixOf)
import Data.Either (isLeft, lefts)
import Data.Maybe (fromMaybe)

import System.FilePath.Posix ((-<.>), (</>), takeDirectory, takeFileName, takeExtension)
import System.Directory (makeAbsolute, doesFileExist, getDirectoryContents)
import System.Posix.Files (nullFileMode, ownerReadMode, ownerWriteMode, unionFileModes, setFileMode)

import System.Console.GetOpt
import System.Environment
import System.Exit

import Data.UUID.V4 (nextRandom)
import qualified Data.UUID as UUID (toString)

import System.IO (stderr, hPutStrLn)
import Control.Monad (when)
import Data.List (nub)

-- TODO : add possibility to change cpCFGdir = "/etc/NetworkManager/system-connections"
-- TODO : change options
-- TODO : split config into config and make


-----------------------
-- arguments / commands management
-----------------------

data Options = Options
    { optHelp        :: Bool
    , optVerbose     :: Bool
    , optShowVersion :: Bool
    , optRename      :: Maybe String
    , optOutput      :: Maybe FilePath
    , optInput       :: Maybe FilePath
    , optLibDirs     :: [FilePath]
    } deriving Show

defaultOptions = Options
    { optHelp        = False
    , optVerbose     = False
    , optShowVersion = False
    , optRename      = Nothing
    , optOutput      = Nothing
    , optInput       = Nothing
    , optLibDirs     = []
    }

data ConfigParams = ConfigParams
    { cpID     :: String
    , cpUUID   :: String
    , cpAuth   :: String
    , cpCipher :: String
    , cpIP     :: String
    , cpPort   :: String
    , cpProt   :: String
    , cpCAfp   :: String
    , cpCRfp   :: String
    , cpKYfp   :: String
    , cpCFGdir :: String
    } deriving Show

defConfigParams = ConfigParams
    { cpID     = ""
    , cpUUID   = ""
    , cpAuth   = ""
    , cpCipher = ""
    , cpIP     = ""
    , cpPort   = ""
    , cpProt   = ""
    , cpCAfp   = ""
    , cpCRfp   = ""
    , cpKYfp   = ""
    , cpCFGdir = "/etc/NetworkManager/system-connections"
    }

data Command
        = Extract               -- extract certificate details and save to files (.cert, .ca, .key)
        | Config                -- make configuration file and save to file
        | Nil                   -- no command
        deriving (Eq,Ord,Show)

toCommand :: String -> Command
toCommand "extract" = Extract
toCommand "config" = Config
toCommand _ = Nil

arity :: Command -> Int
arity Extract = 1
arity Config = 1
arity Nil = 0

arity_err :: Command -> String
arity_err Extract = "extract command: Missing file name."
arity_err Config = "config command: Missing file name."
arity_err Nil = ""

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
-- for testing in ghci:
-- *Main> :main arg1, arg2.., opt1, opt2...

main :: IO ()
main = getArgs >>= compilerOpts >>= doJobs


-----------------------
-- jobs
-----------------------

doJobs :: (Options, [FilePath], Command) -> IO ()
doJobs (args, files, cmd) = do
    putStrLn $ "FILES: " ++ (show files)
    -- putStrLn $ "parsed: " ++ (show (args, files, cmd))
    let fn  = head files -- should be safe...
        -- fn' = fromMaybe fn $ optRename args
        -- fn' = fromMaybe fn $ (replacepath fn) <$> optRename args
    
    -- content <- S.pack <$> readFile fn
    when (takeFileName fn /= "") $ doOneJob args fn cmd
    
    -- if the filepath is a directory, then apply the command to all .ovpn files in this directory
    when (isDirectory fn) $ do
        fps <- filter (\p -> takeExtension p == ".ovpn") <$> getDirectoryContents fn
        putStrLn $ "FPS: " ++ (show fps)
        if fps == []
          then do
            putStrLn $ "Error: No .ovpn files in " ++ fn ++ " directory."
            exitWith (ExitFailure 1)        
        else
            mapM_ (\p -> doOneJob args p cmd) fps
            

    
    --- return()

doOneJob :: Options -> FilePath -> Command -> IO ()
doOneJob args fn cmd = do
    putStrLn $ "FILES2: " ++ (show fn)
    let fn' = fromMaybe fn $ (replacepath fn) <$> optRename args
    content <- S.pack <$> readFile fn

    -- extract and save cert files
    when (cmd == Extract) $ doExtract args fn' content

    -- extract details and create a config file
    when (cmd == Config) $ doConfig args fn' content



-- extract details and create a config file
doConfig :: Options -> FilePath -> ByteString -> IO ()
doConfig args fn' content = do
    certfilestest <- filter not <$> (mapM doesFileExist $ certfilesnms fn')
    
    -- if cert files aren't there, create them
    if certfilestest == [] then return () else doExtract args fn' content
    
    -- cert files absolute paths
    fpca:fpcr:fpky:xs <- mapM makeAbsolute $ certfilesnms fn'  
    
    -- parse ovpn file for relevant details
    let auth'   = maperr1 "auth" $ A.parseOnly pAuth content
        ciph'   = maperr1 "cipher" $ A.parseOnly pCiph content
        remo'   = maperr1 "remote" $ A.parseOnly pIP content
        proto'  = maperr1 "proto" $ A.parseOnly pProto content
        errs    = lefts [auth', ciph', proto'] ++ lefts [remo']
    
    -- exit in case error in parsing details
    if errs /= []
      then do
        putStrLn $ "Error: " ++ (concat errs)
        exitWith (ExitFailure 1)

    else do
        cpuuid <- UUID.toString <$> nextRandom
        let Right auth      = auth'
            Right ciph      = ciph'
            Right proto     = proto'
            Right (ip,port) = remo'
            cpid   = fn' -- "vpn_gate_" ++ ip ++ "_" ++ proto ++ "_" ++ port ++ "_TEST"
        
        let cp = defConfigParams { cpID = cpid, cpUUID = cpuuid
                                 , cpAuth = auth, cpCipher = ciph, cpIP = ip, cpPort = port, cpProt = proto
                                 , cpCAfp = fpca, cpCRfp = fpcr, cpKYfp = fpky
                                 }

        if optVerbose args then do
                    hPutStrLn stderr ("auth: " ++ auth)
                    hPutStrLn stderr ("cipher: " ++ ciph)
                    hPutStrLn stderr ("IP: " ++ ip)
                    hPutStrLn stderr ("port: " ++ port)
                    hPutStrLn stderr ("proto: " ++ proto)
                    hPutStrLn stderr ("\nfile output:\n" ++ confStr cp)
                    -- hPutStrLn stderr ("\nall saved in:\n" ++ fpca ++ "\n" ++ fpcr ++ "\n" ++ fpky)
           else return()
        
        -- saving config file
        let fp = cpCFGdir cp </> cpID cp
        writeFile fp $ confStr cp
        -- NetworkManager requires no permission for group and others
        sequence $ map (setFileMode fp) [nullFileMode, unionFileModes ownerReadMode ownerWriteMode]
        
    return ()

-- extract ca, cert and key strings and store them in .ca, .cert, .key files
doExtract :: Options -> FilePath -> ByteString -> IO ()
doExtract args fn' content = do
    let ca'   = maperr1 "ca" $ A.parseOnly (grab ca_prms) content
        cert' = maperr1 "cert" $ A.parseOnly (grab cert_prms) content
        key'  = maperr1 "key" $ A.parseOnly (grab key_prms) content
        errs   = lefts [ca', cert', key']

    if errs /= []
      then do
        putStrLn $ "Error: " ++ (concat errs)
        exitWith (ExitFailure 1)

    else do let Right ca   = ca'
                Right cert = cert'
                Right key  = key'
                fpca:fpcr:fpky:xs = certfilesnms fn'

            if optVerbose args then do
                    hPutStrLn stderr ("\nca string:\n" ++ ca)
                    hPutStrLn stderr ("\ncert string:\n" ++ cert)
                    hPutStrLn stderr ("\nkey string:\n" ++ key)
                    hPutStrLn stderr ("\nall saved in:\n" ++ fpca ++ "\n" ++ fpcr ++ "\n" ++ fpky)
               else return()

            writeFile fpca ca
            writeFile fpcr cert
            writeFile fpky key

----------------------
-- argument management
----------------------

options :: [OptDescr (Options -> Options)]
options =
    [ Option ['h','?'] ["help"]    (NoArg (\ opts -> opts { optHelp = True }))                                      "print this help message."
    , Option ['v']     ["verbose"] (NoArg (\ opts -> opts { optVerbose = True }))                                   "chatty output on stderr."
    , Option []        ["version"] (NoArg (\ opts -> opts { optShowVersion = True }))                               "show version number."
    , Option ['r']     ["rename"]  (ReqArg (\ fn opts -> opts { optRename = Just fn }) "DIR")                       "rename the output files."
    , Option ['o']     ["output"]  (OptArg ((\ f opts -> opts { optOutput = Just f }) . fromMaybe "output") "FILE") "output FILE"
    , Option ['c']     []          (OptArg ((\ f opts -> opts { optInput = Just f }) . fromMaybe "input") "FILE")   "input FILE"
    , Option ['L']     ["libdir"]  (ReqArg (\ d opts -> opts { optLibDirs = optLibDirs opts ++ [d] }) "DIR")        "library directory"
    ]

compilerOpts :: [String] -> IO (Options, [String], Command)
compilerOpts argv =
  case getOpt Permute options argv of
     (o',n'',[]  ) -> do
        let o = foldl (flip id) defaultOptions o'
        -- print help if -h detected, and success exit
        when (optHelp o) $ do
            hPutStrLn stderr (usageInfo header options)
            exitWith ExitSuccess
        -- print version if --version detected, and success exit
        when (optShowVersion o) $ do
            hPutStrLn stderr "Version 0.1.0."
            exitWith ExitSuccess
        -- failure exit if no command names detected (i.e. ovpn somecmd etc...)
        when (null n'') $ do
            hPutStrLn stderr "No command name provided."
            exitWith (ExitFailure 1)
        let x:n' = n''
            cmd = toCommand x
        -- failure exit if command is not a valid command name
        when (cmd == Nil) $ do
            hPutStrLn stderr $ x ++ " is not a command name."
            exitWith (ExitFailure 1)
        -- failure exit if not enough command arguments (typically filenames)
        when (arity cmd > length n') $ do
            hPutStrLn stderr $ arity_err cmd
            exitWith (ExitFailure 1)
        let n = take (arity cmd) n'
        return (o, n, cmd)
     (_,_,errs) -> ioError (userError (concat errs ++ usageInfo header options))
 where header = "Usage: ovpn [COMMAND...] FILE [OPTION...]"

----------------------
-- parser functions
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

pSimple :: String -> Parser String
pSimple s = do
    A.manyTill A.anyChar $ do A.endOfLine  -- FIXME : should add an alternative if the key string is at the begining of the file
                              A.string $ S.pack s
                              A.many1 (A.char ' ')
    x <- A.manyTill A.anyChar $ A.eitherP A.endOfLine A.endOfInput
    return x

-- | parse what comes after the "auth" line
pAuth :: Parser String
pAuth = pSimple "auth"

-- | parse what comes after the "cipher" line
pCiph :: Parser String
pCiph = pSimple "cipher"

-- | parse what comes after the "proto" line
pProto :: Parser String
pProto = pSimple "proto"

-- | return (IP, Port) from "bla remote 255.1.23.255 1234 bla\n" type strings
pIP :: Parser (String, String)
pIP = do
    A.manyTill A.anyChar $ do A.endOfLine   -- FIXME : should add an alternative if the key string is at the begining of the file
                              A.string $ "remote"
                              A.many1 (A.char ' ')
    x <- A.sepBy1 (A.many1 A.digit) (A.char '.')
    A.many1 (A.char ' ')
    y <- A.manyTill (A.digit) $ A.eitherP A.endOfLine A.endOfInput
    return $ (concat $ intersperse "." x, y)


----------------------
-- argtest
----------------------

confStr :: ConfigParams -> String
confStr cp =
 "[connection]\n\
    \id="++ cpID cp ++ "\n\
    \uuid="++ cpUUID cp ++ "\n\
    \type=vpn\n\
    \ \n\
    \[vpn]\n\
    \service-type=org.freedesktop.NetworkManager.openvpn\n\
    \connection-type=tls\n\
    \auth="++ cpAuth cp ++ "\n\
    \remote="++ cpIP cp ++ "\n\
    \cipher="++ cpCipher cp ++ "\n\
    \cert-pass-flags=0\n\
    \port="++ cpPort cp ++ "\n\
    \cert="++ cpCRfp cp ++ "\n\
    \ca="++ cpCAfp cp ++ "\n\
    \key="++ cpKYfp cp ++ "\n\
    \ \n\
    \[ipv6]\n\
    \method=auto\n\
    \ \n\
    \[ipv4]\n\
    \method=auto"

----------------------
-- local question
----------------------
-- needed to improve the error messages sent by ParseOnly
mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left x)  = Left $ f x
mapLeft _ (Right x) = Right x

-- error msg template
errmap1 :: String -> (a -> String)
errmap1 s = const $ "Couldn't find '" ++ s ++ "' details. "

maperr1 s = mapLeft $ errmap1 s

certfilesnms :: String -> [String]
certfilesnms fn = map (fn -<.>) ["ca", ".cert", ".key"]

replacepath :: FilePath -> FilePath -> FilePath
replacepath fp1 fp2 = dir2 </> fn2
    where dir1 = takeDirectory fp1
          fn1  = takeFileName fp1
          dir2 = let d2 = takeDirectory fp2 in if d2 == "." && (not $ d2 `isPrefixOf` fp2) then dir1 else d2
          fn2  = let f2 = takeFileName fp2 in if f2 == "" then fn1 else f2

-- hasDirectory "foo" is False, hasDirectory "./foo", "./foo/" "./bar/foo", etc are True
hasDirectory :: FilePath -> Bool
hasDirectory fp = let d = takeDirectory fp in if d == "." && (not $ d `isPrefixOf` fp) then False else True

isDirectory :: FilePath -> Bool
isDirectory fp = hasDirectory fp && takeFileName fp == ""







