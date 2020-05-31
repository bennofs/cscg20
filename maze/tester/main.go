package main

import (
	"encoding/json"
	"flag"
	"log"
	"bytes"
	"math"
	"os"
	"time"
	"fmt"

	"five.name/cscg/maze"
)

const (
	TimeScale = uint64(100000000)
	Step = maze.MaxStep
)

type Route struct {
	Points []maze.MapPos
}

var t uint64

func getPos(s *maze.Session) (maze.MapPos, error) {
	var finalTeleport maze.TeleportResponse
	errc := s.Conn.WaitForMessage(&finalTeleport)
	err := s.SendState(maze.PlayerState{
		Time: (t + 1) * TimeScale,
		Pos:  [3]int32{0xfffff * 1000, 20000, 0xfffff * 1000},
	})
	t += 1
	if err != nil {
		return maze.MapPos{}, fmt.Errorf("send state: %v", err)
	}

	err = <-errc
	return maze.MapPosFromGame(finalTeleport.Pos), err
}

func followRoute(s *maze.Session, pos maze.MapPos, route Route, delay time.Duration) (maze.MapPos, error) {
	var finalTeleport maze.TeleportResponse
	errc := s.Conn.WaitForMessage(&finalTeleport)

	for _, target := range route.Points {
		for pos != target {
			dx := (target.X - pos.X)
			dy := (target.Y - pos.Y)

			if dx*dx+dy*dy > Step*Step {
				norm := math.Sqrt(float64(dx*dx + dy*dy))
				dx = dx * Step / int32(norm+1)
				dy = dy * Step / int32(norm+1)
			}

			pos.X += dx
			pos.Y += dy

			err := s.SendState(maze.PlayerState{
				Time: (t + 1) * TimeScale,
				Pos:  [3]int32{pos.X * 1000, 20000, pos.Y * 1000},
			})
			if err != nil {
				return maze.MapPos{}, fmt.Errorf("send state: %v", err)
			}

			time.Sleep(delay)
			t += 1
		}
	}
	err := s.SendState(maze.PlayerState{
		Time: (t + 1) * TimeScale,
		Pos:  [3]int32{0xfffff * 1000, 20000, 0xfffff * 1000},
	})
	t += 1
	if err != nil {
		return maze.MapPos{}, fmt.Errorf("send state: %v", err)
	}

	err = <-errc
	return maze.MapPosFromGame(finalTeleport.Pos), err
}

func main() {
	routeFileName := flag.String("route", "route.json", "route to load")
	delayArg := flag.Duration("delay", 5*time.Millisecond, "delay between successive packets")
	s, initTeleport, err := maze.CreateSession(true)
	if err != nil {
		log.Fatalf("create session: %v", err)
	}

	f, err := os.Open(*routeFileName)
	if err != nil {
		log.Fatalf("open route file: %v", err)
	}

	var route Route
	err = json.NewDecoder(f).Decode(&route)
	if err != nil {
		log.Fatalf("deserialize route: %v", err)
	}

	s.Conn.RegisterTextHandlers()
	s.Conn.RegisterCheckpointLogger()
	s.Conn.RegisterTeleportLogger()
	s.SendHeartbeat(0)

	var firstBeat maze.HeartbeatResponse
	err = <-s.Conn.WaitForMessage(&firstBeat)
	if err != nil {
		log.Fatalf("receive first heartbeat: %V", err)
	}

	s.Conn.AddHandler(func(payload []byte) bool {
		var logout maze.ForceLogoutResponse
		if ok, _ := logout.Parse(payload); ok {
			log.Fatalf("received logout");
		}
		return false
	})

	pos := maze.MapPosFromGame(initTeleport.Pos)
	delay := *delayArg
	t = firstBeat.Time + 1
	pos, err = followRoute(s, pos, route, delay);
	if err != nil {
		log.Fatalf("follow route: %v", err)
	}
	log.Printf("at pos: %v", pos);

	// try a double step
	var out bytes.Buffer
	firstStep := maze.StateRequest {
		Secret: s.Secret,
			MyState: maze.PlayerState {
			Time: (t + 1) * TimeScale,
				Pos:  [3]int32{Step * 1000, 20000, 0 * 1000},
		},
	}
	t += 1
	secondStep := maze.StateRequest {
		Secret: s.Secret,
			MyState: maze.PlayerState {
			Time: (t + 1) * TimeScale,
				Pos:  [3]int32{Step * 1000, 20000, 0 * 1000},
		},
	}
	t += 1
	out.Write(maze.EncodeMessage(&firstStep))
	out.Write(maze.EncodeMessage(&secondStep))
	_, err = s.Conn.WriteRaw(out.Bytes())

	pos, err = getPos(s)
	if err != nil {
		log.Fatalf("get position: %v", err)
	}
	log.Printf("new position: %v", pos)
}
