package main

import (
	"flag"
	"fmt"
	"github.com/nsheridan/wkfs/s3"
	"github.com/tkandal/cashier/lib"
	"github.com/tkandal/cashier/server"
	"github.com/tkandal/cashier/server/config"
	"github.com/tkandal/cashier/server/wkfs/vaultfs"
	"log"
	"os"
	"path/filepath"
)

var (
	cfg     = flag.String("config_file", "cashierd.conf", "Path to configuration file.")
	version = flag.Bool("version", false, "Print version and exit")
)

func main() {
	if err := realMain(); err != nil {
		os.Exit(1)
	}
}

func realMain() error {
	flag.Parse()
	if *version {
		_, _ = fmt.Fprintf(os.Stdout, "%s\n", lib.Version)
		return nil
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile | log.LUTC)
	log.SetPrefix(filepath.Base(os.Args[0] + ": "))

	conf, err := config.ReadConfig(*cfg)
	if err != nil {
		log.Printf("read config failed; error = %v\n", err)
		return err
	}

	// Register well-known filesystems.
	if conf.AWS == nil {
		conf.AWS = &config.AWS{}
	}
	s3.Register(&s3.Options{
		Region:    conf.AWS.Region,
		AccessKey: conf.AWS.AccessKey,
		SecretKey: conf.AWS.SecretKey,
	})
	vaultfs.Register(conf.Vault)

	// Start the server
	server.Run(conf)
	return nil
}
