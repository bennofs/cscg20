package main

import (
	"log"

	"five.name/cscg/maze"
)

func run() error {
	s, _, err := maze.CreateSession(true)
	if err != nil {
		return err
	}
	defer s.Close()

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
