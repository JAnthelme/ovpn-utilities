{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}

module Main where

import Data.Attoparsec.ByteString.Char8 (Parser)
import qualified Data.Attoparsec.ByteString.Char8 as A (parseOnly, manyTill, anyChar, string, endOfLine, eitherP, endOfInput, sepBy1, many1, digit, char)
import Data.ByteString.Char8 (ByteString)
import qualified Data.ByteString.Char8 as S (pack)
import System.FilePath.Posix ((-<.>))
import Data.List (uncons, intersperse)
import Data.Either (isLeft, lefts)
import Data.Maybe (fromMaybe)

import System.Console.GetOpt
import System.Environment
import System.Exit

import Data.UUID.V4 (nextRandom)
import qualified Data.UUID as UUID (toString)

import System.IO (stderr, hPutStrLn)
import Control.Monad (when)
import Data.List (nub)

-- import Control.Monad.Writer

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
    , cpCAfp   :: String
    , cpCRfp   :: String
    , cpKYfp   :: String
    } deriving Show

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
    -- putStrLn $ "parsed: " ++ (show (args, files, cmd))
    let fn  = head files -- should be safe...
        fn' = fromMaybe fn $ optRename args
    content <- S.pack <$> readFile fn

    -- extract and save cert files
    when (cmd == Extract) $ doExtract args fn' content
    
    -- extract details and create a config file
    when (cmd == Config) $ doConfig args fn' content



-- extract details and create a config file
doConfig :: Options -> FilePath -> ByteString -> IO ()
doConfig args fn' content = do 
    let auth'   = maperr1 "auth" $ A.parseOnly pAuth content
        ciph'   = maperr1 "cipher" $ A.parseOnly pCiph content
        remo'   = maperr1 "remote" $ A.parseOnly pIP content
        errs    = lefts [auth', ciph'] ++ lefts [remo']

    if errs /= []
      then do
        putStrLn $ "Error: " ++ (concat errs)
        exitWith (ExitFailure 1)
    else do
        cpuuid <- UUID.toString <$> nextRandom
        let Right auth      = auth'
            Right ciph      = ciph'
            Right (ip,port) = remo'
            cpid   = "vpn_gate_" ++ ip ++ "_" ++ port ++ "_TEST"
            -- cpuuid = "336cbc40-b42e-44c0-ba7e-6d76a1716710"
            (fpca, fpcr, fpky) = certfilesnms fn'
            cp = ConfigParams {cpID = cpid, cpUUID = cpuuid, cpAuth = auth, cpCipher = ciph, cpIP = ip, cpPort = port
                              , cpCAfp = fpca, cpCRfp = fpcr, cpKYfp = fpky}
        
            
        if optVerbose args then do
                    hPutStrLn stderr ("auth: " ++ auth)
                    hPutStrLn stderr ("cipher: " ++ ciph)
                    hPutStrLn stderr ("IP: " ++ ip)
                    hPutStrLn stderr ("port: " ++ port)
                    hPutStrLn stderr ("\nfile output:\n" ++ confStr cp)
                    -- hPutStrLn stderr ("\nall saved in:\n" ++ fpca ++ "\n" ++ fpcr ++ "\n" ++ fpky)
           else return()
    return ()

-- extract ca, cert and key strings and store them in .ca, .cert, .key files
doExtract :: Options -> FilePath -> ByteString -> IO ()
doExtract args fn' content = do
    let ca'   = A.parseOnly (grab ca_prms) content
        cert' = A.parseOnly (grab cert_prms) content
        key'  = A.parseOnly (grab key_prms) content
        errheader = map (\s -> "Error: could not find \'" ++ s ++ "\' data") ["ca","cert","key"]
        errcheck  = checkResults errheader [ca',cert',key']

    if errcheck /= []
      then do
        putStrLn $ concat errcheck
        exitWith (ExitFailure 1)
    else do let ca:cert:key:xs =  getResults [ca',cert',key']
                fpca = fn' -<.> "ca"
                fpcr = fn' -<.> ".cert"
                fpky = fn' -<.> ".key"

            if optVerbose args then do
                    hPutStrLn stderr ("\nca string:\n" ++ ca)
                    hPutStrLn stderr ("\ncert string:\n" ++ cert)
                    hPutStrLn stderr ("\nkey string:\n" ++ key)
                    hPutStrLn stderr ("\nall saved in:\n" ++ fpca ++ "\n" ++ fpcr ++ "\n" ++ fpky)
               else return()

            writeFile fpca ca
            writeFile fpcr cert
            writeFile fpky key
{-
fromParser :: Either String String -> IO (Bool, String)
fromParser p = case p of
    Left x  -> return (True, x)
    Right y -> return (False, y)
-}

options :: [OptDescr (Options -> Options)]
options =
    [ Option ['h','?'] ["help"]    (NoArg (\ opts -> opts { optHelp = True }))                                      "print this help message."
    , Option ['v']     ["verbose"] (NoArg (\ opts -> opts { optVerbose = True }))                                   "chatty output on stderr."
    , Option []        ["version"] (NoArg (\ opts -> opts { optShowVersion = True }))                               "show version number."
    , Option ['r']     ["rename"]  (ReqArg (\ fn opts -> opts { optRename = Just fn }) "DIR")                       "rename the output file"
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


-- | return (IP, Port) from "bla remote 255.1.23.255 1234 bla\n" type strings
pIP :: Parser (String, String)
pIP = do
    A.manyTill A.anyChar $ do A.endOfLine   -- FIXME : should add an alternative if the key string is at the begining of the file
                              A.string $ "remote"
                              A.many1 (A.char ' ')
    -- A.many1 (A.char ' ')
    x <- A.sepBy1 (A.many1 A.digit) (A.char '.')
    A.many1 (A.char ' ')
    y <- A.manyTill (A.digit) $ A.eitherP A.endOfLine A.endOfInput
    return $ (concat $ intersperse "." x, y)


----------------------
-- argtest
----------------------
foo :: IO ()
foo  = do
        bar <- getArgs
        putStrLn $ show bar


-- cpID = cpid, cpUUID = cpuuid, cpAuth = auth, cpCipher = ciph, cpIP = ip, cpPort = port
   --                           , cpCAfp = fpca, cpCRfp = fpcr, cpKYfp = fpky

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
checkResults :: [String] -> [Either String a] -> [String]
checkResults lbls res = map g $ filter (isLeft . snd) $ zip lbls res
    where -- f = isLeft . snd
          -- f (_, Left _)  = True
          -- f (_, Right _) = False
          g (s, Left e)  = s ++ ": " ++ e
          g (s, Right _) = ""

getResults :: [Either String a] -> [a]
getResults res = concatMap f res
    where f (Left  x)  = []
          f (Right x)  = [x]

mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left x)  = Left $ f x
mapLeft _ (Right x) = Right x

errmap1 :: String -> (a -> String)
errmap1 s = const $ "Couldn't find '" ++ s ++ "' details. "

maperr1 s = mapLeft $ errmap1 s

certfilesnms :: String -> (String, String, String)
certfilesnms fn' = (fn' -<.> "ca", fn' -<.> ".cert", fn' -<.> ".key")

{-
main2 :: IO ()
main2 = do
    xxx <- getArgs
    -- (args, files) <- getArgs >>= parse
    (args, files, cmd) <- getArgs >>= compilerOpts

    putStrLn $ "getArgs: " ++ (show xxx)
    putStrLn $ "parsed: " ++ (show (args, files, cmd))
    let fn  = head files -- should be safe...
        fn' = fromMaybe fn $ optRename args
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
    else do if optVerbose args then do
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

-}





