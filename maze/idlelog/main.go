package main

import (
	"log"
	"time"
	"flag"
	"os/exec"

	"five.name/cscg/maze"
)

func run() error {
	intervalArg := flag.String("interval", "500ms", "time to wait between successive state updates")
	uidArg := flag.Int("uid", 398, "uid to watch for idleness")
	maxIdle := flag.Duration("maxidle", 60 * time.Second, "max time of idle position before killing the process")
	s, initTeleport, err := maze.CreateSession(true)

	if err != nil {
		return err
	}
	defer s.Close()

	interval, err := time.ParseDuration(*intervalArg)
	if err != nil {
		return err
	}

	s.Conn.RegisterStateLogger()
	s.Conn.RegisterTeleportLogger()
	s.Conn.RegisterHeartbeatLogger()
	s.Conn.RegisterForceLogoutLogger()

	state := maze.PlayerState{
		Time: 0,
		Pos:  initTeleport.Pos,
	}

	var lastPos [3]int32
	lastPosChange := time.Now()
	s.Conn.AddHandler(func(payload []byte) bool {
		var s maze.StateResponse
		if matched, err := s.Parse(payload); matched {
			if err != nil {
				log.Printf("state parse error: %v", err)
			}

			for _, p := range(s.Players) {
				if int(p.Uid) == *uidArg {
					if lastPos != p.State.Pos {
						lastPosChange = time.Now()
						lastPos = p.State.Pos
					}
				}
			}

			if time.Since(lastPosChange) > *maxIdle {
				log.Printf("idle detected, killing processes")
				err := exec.Command("/usr/bin/pkill", flag.Args()...).Run()
				if err != nil {
					log.Printf("pkill error: %v", err)
				}
				lastPosChange = time.Now()
			}
		}

		return false
	})

	for {
		s.SendHeartbeat(state.Time)
		s.SendState(state)
		time.Sleep(interval)
		state.Time += uint64(interval.Milliseconds())
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
