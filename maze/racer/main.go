package main

import (
	"encoding/json"
	"flag"
	"log"
	"math"
	"os"
	"time"

	"five.name/cscg/maze"
)

const (
	TimeScale = uint64(100000000)
)

type Route struct {
	Points []maze.MapPos
}

func main() {
	routeFileName := flag.String("route", "route.json", "route to load")
	stepArg := flag.Int("maxstep", maze.MaxStep, "maximum units to step in a single packet")
	delayArg := flag.Duration("delay", 5*time.Millisecond, "delay between successive packets")
	repeat := flag.Int("repeat", 1, "number of times each state packet is sent")
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

	var logout maze.ForceLogoutResponse
	logoutc := s.Conn.WaitForMessage(&logout)

	var finalTeleport maze.TeleportResponse
	errc := s.Conn.WaitForMessage(&finalTeleport)
	route.Points = append(route.Points, maze.MapPos{-0xffff, -0xffff})

	pos := maze.MapPosFromGame(initTeleport.Pos)
	step := int32(*stepArg)
	delay := *delayArg
	t := firstBeat.Time + 1
	sleepDuration := 100 * time.Millisecond

	checkpoint0Pos := maze.MapPos { X: 2046, Y: 1945 }

	for _, target := range route.Points {
		remainingRepeat := 0
		if target == checkpoint0Pos {
			sleepDuration = delay / time.Duration(*repeat)
			log.Printf("going into race mode: %v", sleepDuration)
		}
		for pos != target || remainingRepeat > 0 {
			if remainingRepeat == 0 {
				remainingRepeat = *repeat
				dx := (target.X - pos.X)
				dy := (target.Y - pos.Y)

				if dx*dx+dy*dy > step*step {
					log.Printf("max step exceed!");
					norm := math.Sqrt(float64(dx*dx + dy*dy))
					dx = dx * step / int32(norm+1)
					dy = dy * step / int32(norm+1)
				}

				pos.X += dx
				pos.Y += dy
			}
			remainingRepeat -= 1

			err := s.SendState(maze.PlayerState{
				Time: (t + 1) * TimeScale,
				Pos:  [3]int32{pos.X * 1000, 20000, pos.Y * 1000},
			})
			if err != nil {
				log.Fatalf("send state error: %v", err)
			}

			time.Sleep(sleepDuration)
			t += 1
		}
	}

	select {

	case err = <-errc:
		if err != nil {
			log.Fatalf("wait for teleport: %v", err)
		}
		log.Printf("reached pos %v", maze.MapPosFromGame(finalTeleport.Pos))

	case err = <-logoutc:
		if err != nil {
			log.Fatalf("wait for logout: %v", err)
		}
		log.Fatalf("force disconnected")

	}
}
