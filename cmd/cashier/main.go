package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path"
	"time"

	"github.com/pkg/browser"
	"github.com/spf13/pflag"
	"github.com/tkandal/cashier/client"
	"github.com/tkandal/cashier/lib"
	"golang.org/x/crypto/ssh/agent"
)

var (
	u, _    = user.Current()
	cfg     = pflag.String("config", path.Join(u.HomeDir, ".cashier.conf"), "Path to config file")
	_       = pflag.String("ca", "http://localhost:10000", "CA server")
	_       = pflag.Int("key_size", 0, "Size of key to generate. Ignored for ed25519 keys. (default 2048 for rsa keys, 256 for ecdsa keys)")
	_       = pflag.Duration("validity", time.Hour*24, "Key lifetime. May be overridden by the CA at signing time")
	_       = pflag.String("key_type", "rsa", "Type of private key to generate - rsa, ecdsa or ed25519. (default \"rsa\")")
	_       = pflag.String("key_file_prefix", "", "Prefix for filename for public key and cert (optional, no default)")
	version = pflag.Bool("version", false, "Print version and exit")
)

func main() {
	pflag.Parse()
	if *version {
		fmt.Printf("%s\n", lib.Version)
		os.Exit(0)
	}
	log.SetPrefix("cashier: ")
	log.SetFlags(0)

	c, err := client.ReadConfig(*cfg)
	if err != nil {
		log.Printf("Configuration error: %v\n", err)
	}
	_, _ = fmt.Fprintln(os.Stdout, "Generating new key pair")
	priv, pub, err := client.GenerateKey(client.KeyType(c.Keytype), client.KeySize(c.Keysize))
	if err != nil {
		log.Fatalln("Error generating key pair: ", err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "Your browser has been opened to visit %s\n", c.CA)
	if err := browser.OpenURL(c.CA); err != nil {
		fmt.Println("Error launching web browser. Go to the link in your web browser")
	}

	_, _ = fmt.Fprint(os.Stdout, "Enter token: ")
	scanner := bufio.NewScanner(os.Stdin)
	var buffer bytes.Buffer
	for scanner.Scan(); scanner.Text() != "."; scanner.Scan() {
		buffer.WriteString(scanner.Text())
	}
	tokenBytes, err := base64.StdEncoding.DecodeString(buffer.String())
	if err != nil {
		log.Fatalln(err)
	}
	token := string(tokenBytes)

	cert, err := client.Sign(pub, token, c)
	if err != nil {
		log.Fatalln(err)
	}
	sock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatalf("Error connecting to agent: %v\n", err)
	}
	defer func() {
		_ = sock.Close()
	}()
	a := agent.NewClient(sock)
	if err := client.InstallCert(a, cert, priv); err != nil {
		log.Fatalln(err)
	}
	if err := client.SavePublicFiles(c.PublicFilePrefix, cert, pub); err != nil {
		log.Fatalln(err)
	}
	if err := client.SavePrivateFiles(c.PublicFilePrefix, cert, priv); err != nil {
		log.Fatalln(err)
	}
	_, _ = fmt.Fprintln(os.Stdout, "Credentials added.")
}
