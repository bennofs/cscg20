package main

import (
	"time"
	"log"
	"fmt"
	"five.name/cscg/maze"
)

const (
	MaxSpeed = 60
	MaxStep = 1000000
)

const (
	BisectWork = iota
	BisectVerifyUpper
	BisectUpperVerified
	BisectVerifyLower
)

func bisectTeleport(s *maze.Session, action func(maze.HeartbeatResponse, int32)) (int32, error) {
	packets, done := s.Conn.PacketChannel()
	defer close(done)

	lastStateChange := time.Now()
	state := BisectWork
	upper := int32(MaxStep + 100)
	current := int32(0)
	fallback := int32(0)

	for packet := range(packets) {
		var teleport maze.TeleportResponse
		var beat maze.HeartbeatResponse

		// if we get a teleport, we made an invalid move
		if matched, err := teleport.Parse(packet); matched {
			if err != nil {
				return current, err
			}

			if state == BisectVerifyUpper {
				state = BisectUpperVerified
				lastStateChange = time.Now()
				continue
			}

			// fallback is too high
			if fallback == current {
				fallback -= upper - current
				current = fallback
			} else {
				upper = current
				current = fallback
			}

			continue
		}

		if matched, err := beat.Parse(packet); matched {
			if err != nil {
				return current, err
			}

			if current + 1 == upper {
				now := time.Now()

				if now.Sub(lastStateChange).Seconds() > 3 {
					// this is good, no teleport, so we are done
					if state == BisectVerifyLower {
						return current, nil;
					}

					// this is bad, we should've gotten a teleport
					// it means that the upper bound is too low
					// increase upper and return to normal state
					if state == BisectVerifyUpper {
						state = BisectWork
						fallback = upper
						current = (upper + fallback) / 2
						upper += MaxStep
						action(beat, current)
						continue
					}
				}

				// verification of upper value complete,
				// begin verifying lower bound
				if state == BisectUpperVerified {
					state = BisectVerifyLower
					lastStateChange = now
					action(beat, current)
					continue
				}

				// just wait until timer expires
				if state == BisectVerifyLower {
					continue
				}

				if state == BisectWork {
					state = BisectVerifyUpper
					lastStateChange = now
					action(beat, upper)
					continue
				}

				if state != BisectVerifyUpper {
					panic(fmt.Sprintf("illegal state %v, expected BisectVerifyUpper", state))
				}
			}

			fallback = current
			current = (current + upper) / 2
			action(beat, current)
			continue
		}
	}

	return current, nil
}

func findWall(s *maze.Session, baseState *maze.PlayerState) (int32, error) {
	stopPacemaker := s.StartPacemaker(100 * time.Millisecond, baseState.Time)
	defer close(stopPacemaker)

	return bisectTeleport(s, func(beat maze.HeartbeatResponse, v int32) {
		baseState.Time = beat.Time * 10000
		state := *baseState
		state.Pos[0] += v * 1000

		s.SendState(state)
	})
}

func findMaxStep(s *maze.Session, baseState *maze.PlayerState) (int32, error) {
	stopPacemaker := s.StartPacemaker(100 * time.Millisecond, baseState.Time)
	defer close(stopPacemaker)

	maxMove, err := bisectTeleport(s, func(beat maze.HeartbeatResponse, v int32) {
		log.Printf("send speed %v", v)
		baseState.Time = beat.Time * 10000
		state := *baseState

		// move back
		state.Time = beat.Time
		state.Pos[0] -= v
		s.SendState(state)

		time.Sleep(500 * time.Millisecond)

		// move forward
		state = *baseState
		state.Time = beat.Time * 10000 + 10000
		state.Pos[0] += v
		s.SendState(state)
	})
	if err != nil {
		return maxMove, err
	}

	return maxMove, err
}


func run() (err error) {
	s, initTeleport, err := maze.CreateSession(true)
	if err != nil {
		return
	}
	defer s.Close()

	s.Conn.RegisterTextHandlers()
	s.Conn.RegisterTeleportLogger()

	state := maze.PlayerState {
		Time: 0,
		Pos: initTeleport.Pos,
	}

	// find wall
	w, err := findWall(s, &state)
	log.Printf("found wall: %d", state.Pos[0] + w)

	// find max speed
	state.Pos[0] += w * 1000
	maxSpeed, err := findMaxStep(s, &state)
	log.Printf("max speed: %v", maxSpeed)


	//s.Conn.RegisterHeartbeatLogger()
	state.Pos[0] = 0
	for {
		s.SendState(state)
		time.Sleep(3 * time.Second)
		state.Time += 1
	}

	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("error: %v\n", err)
	}
}
