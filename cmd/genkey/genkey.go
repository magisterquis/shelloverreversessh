// Program genkey generates keys for shelloverreversessh.
package main

/*
 * genkey.go
 * Generates keys for shelloverreversessh.
 * By J. Stuart McMurray
 * Created 20220201
 * Last Modified 20220201
 */

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/ssh"
)

func main() {
	var (
		fileName = flag.String(
			"out",
			"key",
			"Output `file` name",
		)
		pubSuffix = flag.String(
			"pub-suffix",
			".pub",
			"Public key file `suffix`",
		)
		verbOn = flag.Bool(
			"v",
			false,
			"Enable verbose logging",
		)
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %s [options]

Generates a keypair suitable for use with shelloverreversessh.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Generate a key. */
	ku, kr, err := ed25519.GenerateKey(nil)
	if nil != err {
		log.Fatalf("Error generating key: %s", err)
	}

	/* Work out the public key in OpenSSH-friendly form. */
	sku, err := ssh.NewPublicKey(ku)
	if nil != err {
		log.Fatalf("SSHifying public key: %s", err)
	}

	/* Open the output files. */
	rf, err := os.OpenFile(*fileName, os.O_CREATE|os.O_WRONLY, 0600)
	if nil != err {
		log.Fatalf("Unable to open key file %q: %s", *fileName, err)
	}
	defer rf.Close()
	ufn := *fileName + *pubSuffix
	uf, err := os.OpenFile(ufn, os.O_CREATE|os.O_WRONLY, 0644)
	if nil != err {
		log.Fatalf("Unable to open public key file %q: %s", ufn, err)
	}
	defer uf.Close()

	/* Write the keys themselves. */
	if _, err := io.WriteString(
		rf,
		base64.RawStdEncoding.EncodeToString(kr),
	); nil != err {
		log.Fatalf("Writing private key to %s: %s", rf.Name(), err)
	}
	if _, err := uf.Write(ssh.MarshalAuthorizedKey(sku)); nil != err {
		log.Fatalf("Writing public key to %s: %s", uf.Name(), err)
	}

	if *verbOn {
		log.Printf("Wrote keypair to %s and %s", rf.Name(), uf.Name())
	}
}
