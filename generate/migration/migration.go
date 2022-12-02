package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"
)

const (
	dateFormat     = "20060102150405"
	migrationsPath = "server/store/migrations"
)

var (
	contents = []byte(`-- +migrate Up


-- +migrate Down`)
)

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: migration <migration name>")
	}
	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
	}
	name := fmt.Sprintf("%s_%s.sql", time.Now().UTC().Format(dateFormat), flag.Arg(0))
	gitRoot, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		log.Fatal(err)
	}
	root := strings.TrimSpace(string(gitRoot))
	ents, err := os.ReadDir(path.Join(root, migrationsPath))
	if err != nil {
		log.Fatal(err)
	}
	for _, e := range ents {
		if e.IsDir() {
			filename := path.Join(migrationsPath, e.Name(), name)
			fmt.Printf("Wrote empty migration file: %s\n", filename)
			// #nosec
			if err := os.WriteFile(filename, contents, os.FileMode(0644)); err != nil {
				log.Fatal(err)
			}
		}
	}
}
