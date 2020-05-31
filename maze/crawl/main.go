package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"five.name/cscg/maze"
)

func run() error {
	intervalArg := flag.String("interval", "100ms", "time to wait between successive state updates")
	maxWrites := flag.Int("maxwrites", 30, "save a snapshot of the map after this many writes")
	s, initTeleport, err := maze.CreateSession(true)

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
	s.Conn.RegisterHeartbeatLogger()
	s.Conn.RegisterForceLogoutLogger()

	defer close(s.StartPacemaker(interval, 0, 1))

	posQueue := make([]maze.MapPos, 100)
	posQueue[0] = maze.MapPos{initTeleport.Pos[0] / 1000, initTeleport.Pos[2] / 1000}
	posCur := 0
	posNext := 1
	backtrack := false
	backtracked := false

	mapStore, err := maze.OpenMapStore("map.bin", *maxWrites)
	if err != nil {
		return fmt.Errorf("open map store: %v", err)
	}
	defer mapStore.Close()

	packets, done := s.Conn.PacketChannel()
	defer close(done)
	var lastBeat maze.HeartbeatResponse
	for packet := range packets {
		var text maze.TextResponse
		if matched, err := text.Parse(packet); matched {
			if err != nil {
				return err
			}

			if strings.Contains(strings.ToLower(text.Text), "teleport") {
				log.Printf("discovered teleporter: %s", text.Text)
				mapStore.Add(posQueue[posCur], maze.MAP_TELEPORT)
			}
			continue
		}

		var teleport maze.TeleportResponse
		if matched, err := teleport.Parse(packet); matched {
			if err != nil {
				return err
			}

			if backtracked {
				mapStore.Invalidate(posQueue[posNext])
				backtracked = false
			}

			teleportPos := maze.MapPos{teleport.Pos[0] / 1000, teleport.Pos[2] / 1000}
			mapStore.Add(teleportPos, maze.MAP_FREE)
			mapStore.Add(posQueue[posCur], maze.MAP_WALL)

			backtrack = true
		}

		if matched, err := lastBeat.Parse(packet); matched {
			if err != nil {
				return err
			}

			backtracked = backtrack

			if backtrack {
				backtrack = false
				backtracked = true

				log.Printf("backtrack %v", posQueue[posCur])
				posCur, posNext = (posCur-1+len(posQueue))%len(posQueue), posCur
			} else {
				err := mapStore.Add(posQueue[posCur], maze.MAP_FREE)
				if err != nil {
					return err
				}

				posQueue[posNext] = mapStore.Map.NextPos(posQueue[posCur])
				posCur, posNext = posNext, (posNext+1)%len(posQueue)
			}

			log.Printf("go %v", posQueue[posCur])
			s.SendState(maze.PlayerState{
				Pos:  [3]int32{posQueue[posCur].X * 1000, 20000, posQueue[posCur].Y * 1000},
				Time: lastBeat.Time + uint64(interval.Milliseconds()) + 1,
			})
		}
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v", err)
	}
}
