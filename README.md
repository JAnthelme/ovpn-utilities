# OVPN-utilities
> OpenVPN file management utilities .

## OS
Only tested on a couple of Debian-based distros (Linux Mint 17.2, Ubuntu 14.04).

## Installation
Install the Haskell Tool [Stack](https://docs.haskellstack.org/en/stable/README/).

then from the shell prompt:
```sh
git clone https://github.com/janthelme/ovpn-utilities.git
cd ovpn-utilities
stack build
```

Copy the executable (typically `.stack-work/dist/x86_64-linux/Cabal-1.22.5.0/build/ovpn/ovpn`) to the directory of your choice, ideally present in your `$PATH`, eg `~/.local/bin`. 

## Getting started
From the command line:
```sh
ovpn somefile.ovpn
```
... will extract the relevant data from `somefile.ovpn` and save them to `somefile.ca`, `somefile.cert`, `somefile.key` in the current directory.

```sh
ovpn somefile.ovpn -r /someotherdir/someothername
```
... same as above but save to `/someotherdir/someothername.ca`, `/someotherdir/someothername.cert` and `/someotherdir/someothername.key`.

:main config vpnTEST.ovpn  -v
:main extract vpnTEST.ovpn  -v


## Documentation
From the command line:
```sh
ovpn -h
```

## Built With

* [Stack](https://docs.haskellstack.org/en/stable/README/)


Github: https://github.com/Janthelme/ovpn-utilities