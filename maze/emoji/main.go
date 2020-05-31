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

	err = s.SendEmoji(13)
	if err != nil {
		return err
	}

	err = s.Conn.PrintFlag()
	if err != nil {
		return err
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
