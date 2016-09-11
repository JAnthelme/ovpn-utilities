# OVPN-utilities
> OpenVPN file management utilities .

## OS
Only tested on a couple of Debian-based distros (Linux Mint 17.2, Ubuntu 14.04).

## Installation
Install the Haskell Tool [Stack](https://docs.haskellstack.org/en/stable/README/).

... then from the shell prompt:
```sh
git clone https://github.com/janthelme/ovpn-utilities.git
cd ovpn-utilities
stack build
```

Copy the executable (typically `.stack-work/dist/x86_64-linux/Cabal-1.22.5.0/build/ovpn/ovpn`) to the directory of your choice, ideally one already present in your `$PATH`, eg `~/.local/bin`. 

## Getting started
From the command line:
```sh
sudo ovpn config somedir/somefile.ovpn
```
... will parse a given ovpn file, `somedir/somefile.ovpn`, and save a corresponding config file in `/etc/NetworkManager/system-connections` (which is why the `sudo` command is needed).

... You should then be able to see and use the vpn connection from Network Manager. If this is not the case try to stop and restart it (eg `sudo restart network-manager`). (*)


```sh
sudo ovpn config somedir/
```
... same as above but for *all* `.ovpn` files in the directory provided.

(*) Tip: the files stored in `/etc/NetworkManager/system-connections` should have no read/write/execute permissions for group and other. The program is supposed to take care of this for you.

## Documentation
From the command line:
```sh
ovpn -h
```

## Built With

* [Stack](https://docs.haskellstack.org/en/stable/README/)


Github: https://github.com/Janthelme/ovpn-utilities