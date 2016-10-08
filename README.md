Description
===========
**lightning** are two programs that build a secure tunnel between remote host
and local host. **lightning_local** implements the SOCKS5 protocol with payload
encryption. **lightning_remote** is a stream server sits at the remote end of
the tunnel.

**lightning** requires `libuv`, `openssl` and `crypto`.

Build
=====

    mkdir build && cd build
    cmake ..
    make

Usage
=====

    # on remote host
    sudo ./bin/lightning_remote -h 0.0.0.0 -p 8790 -c aes-256-cfb -s THE_SECRET -u nobody

    # on local host
    sudo ./bin/lightning_local -h 0.0.0.0 -p 1080 -H REMOTE_HOST -P 8790 -c aes-256-cfb -s THE_SECRET -u nobody -g /path/to/proxy.pac

Under MIT license
=================
```
Copyright (c) 2016 neevek <i@neevek.net>
See the file license.txt for copying permission.
```
