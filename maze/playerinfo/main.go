package main

import (
	"log"
	"flag"

	"five.name/cscg/maze"
)

func run() error {
	s, _, err := maze.CreateSession(false)
	uidArg := flag.Int("uid", 398, "uid to query")
	if err != nil {
		return err
	}
	defer s.Close()

	pi, err := s.RequestInfo(uint32(*uidArg))
	if err != nil {
		return err
	}
	log.Printf("%+v", pi)

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
