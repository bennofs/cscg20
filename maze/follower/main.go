package main

import (
	"flag"
	"fmt"
	"log"
	"time"
	"math/rand"

	"five.name/cscg/maze"
)

const (
	StateExploreForward = iota
	StateBacktrack
	StateFindForward
	StateOnWall
	StateFindTurn
	StateTurn

	ExploreStep = 100
	WallStep    = 1
	MaxStep     = 99
)

var stateName = [...]string {"explore", "backtrack", "forward", "onwall", "findturn", "turn" }

func run() error {
	intervalArg := flag.String("interval", "100ms", "time to wait between successive state updates")
	maxWrites := flag.Int("maxwrites", 30, "save a snapshot of the map after this many writes")
	s, _, err := maze.CreateSession(false)

	if err != nil {
		return err
	}
	defer s.Close()

	interval, err := time.ParseDuration(*intervalArg)
	if err != nil {
		return err
	}

	s.Conn.RegisterTextHandlers()
	s.Conn.RegisterTeleportLogger()
	s.Conn.RegisterForceLogoutLogger()

	defer close(s.StartPacemaker(interval, 0, 100000))

	mapStore, err := maze.OpenMapStore("map.bin", *maxWrites)
	if err != nil {
		return fmt.Errorf("open map store: %v", err)
	}

	mover := maze.NewMover(s, mapStore)
	defer mover.Close()

	rand.Seed(time.Now().Unix())
	nextDir := int8(rand.Intn(8) - 4)
	startPos, err := s.GetPosition()
	if err != nil {
		return fmt.Errorf("cannot get initial position: %v", err)
	}
	for {
		mover.StartFollow <- nextDir
		endPos := <-mover.Done
		centerDir, _ := maze.MajorDirFromTo(endPos, startPos)
		if rand.Intn(3) == 0 {
			nextDir = int8(rand.Intn(8) - 4)
		} else {
			nextDir = int8(centerDir)
		}
	}



	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
