package maze

import (
	"fmt"
	"log"
	"math"
	"strings"
	"time"
)

const (
	StateFindForward = uint8(iota)
	StateBacktrack
	StateOnWall
	StateFindTurn
	StateTurn

	ExploreStep      = 100
	WallStep         = 1
	MaxStep          = 100
	FindForwardLimit = 4000
)

var stateName = [...]string{"forward", "backtrack", "onwall", "findturn", "turn"}

type Mover struct {
	s        *Session
	mapStore *MapStore

	StartStraight chan MapPos
	StartFollow   chan int8
	Stop          chan struct{}

	doneSend chan MapPos
	Done     <-chan MapPos
}

func runStraight(m *Mover, curPos, target MapPos) (MapPos, bool, error) {
	packets, done := m.s.Conn.PacketChannel()
	defer close(done)

	blocked := false
	for {
		select {

		case _, ok := <-m.Stop:
			return curPos, ok, nil

		case packet, ok := <-packets:
			if !ok {
				return curPos, true, fmt.Errorf("packet channel closed during straight run")
			}

			var beat HeartbeatResponse
			if matched, err := beat.Parse(packet); matched {
				if err != nil {
					return curPos, true, fmt.Errorf("hearbeat parse error: %v", err)
				}
				if curPos == target {
					// if the path wasn't blocked, we know our current position
					if !blocked {
						return curPos, true, nil
					}

					// send a fake message to force teleport to verify current position
					err = m.s.SendState(PlayerState{
						Pos:  [...]int32{-0x8ffffff, -0x8ffffff, -0x8ffffff},
						Time: beat.Time + 1,
					})
					if err != nil {
						return curPos, true, fmt.Errorf("send fake state: %v", err)
					}
					continue
				}

				from := curPos

				var dx, dy int32

				if blocked {
					dx = (target.X - curPos.X) / 2
					dy = (target.Y - curPos.Y) / 2
				}

				if dx == 0 && dy == 0 {
					dx = (target.X - curPos.X)
					dy = (target.Y - curPos.Y)
				}

				if dx*dx+dy*dy > MaxStep*MaxStep {
					norm := math.Sqrt(float64(dx*dx + dy*dy))
					dx = dx * MaxStep / int32(norm+1)
					dy = dy * MaxStep / int32(norm+1)
				}

				curPos.X += dx
				curPos.Y += dy

				log.Printf("movement from %v to %v, target %v", from, curPos, target)
				err := m.s.SendState(PlayerState{
					Time: beat.Time + 1,
					Pos:  [3]int32{curPos.X * 1000, 20000, curPos.Y * 1000},
				})
				if err != nil {
					return curPos, true, fmt.Errorf("send state error: %v", err)
				}
			}

			var teleport TeleportResponse
			if matched, err := teleport.Parse(packet); matched {
				if err != nil {
					return curPos, true, fmt.Errorf("teleport parse error: %v", err)
				}

				teleportPos := MapPosFromGame(teleport.Pos)
				m.mapStore.Add(teleportPos, MAP_FREE)
				_, dist := MajorDirFromTo(teleportPos, target)
				if dist <= 1 {
					m.mapStore.Add(target, MAP_WALL)
					return teleportPos, true, nil
				}

				blocked = true
				target = curPos
				curPos = teleportPos
			}

		}
	}

	return curPos, true, nil
}

func runFollow(m *Mover, curPos MapPos, goDir int8) (MapPos, bool, error) {
	packets, done := m.s.Conn.PacketChannel()
	defer close(done)

	// init state
	state := StateFindForward
	findTurnRotations := 0
	findForwardMoves := 0
	var turnDir int8
	var forwardDir uint8
	if goDir >= 0 {
		turnDir = 1
		forwardDir = uint8(goDir)
	} else {
		forwardDir = uint8(goDir + 4)
		turnDir = -1
	}

	iterations := 0
	checkpoints := make(map[MapPos]struct {})

	for {
		select {

		case _, ok := <-m.Stop:
			return curPos, ok, nil

		case packet, ok := <-packets:
			if !ok {
				return curPos, true, fmt.Errorf("packet channel closed during wall following")
			}
			var text TextResponse
			if matched, err := text.Parse(packet); matched {
				if err != nil {
					return curPos, true, err
				}

				if strings.Contains(strings.ToLower(text.Text), "teleport") {
					log.Printf("discovered locked teleporter: %s", text.Text)
					m.mapStore.Add(curPos, MAP_TELEPORT)
				}
				continue
			}

			var beat HeartbeatResponse
			if matched, err := beat.Parse(packet); matched {
				if err != nil {
					return curPos, true, err
				}

				switch state {

				case StateFindForward:
					if findForwardMoves > FindForwardLimit {
						return curPos, true, err
					}
					curPos = curPos.InDir(forwardDir, 1)

				case StateOnWall:
					if iterations > 2000 {
						iterations = 0
						checkpoints[curPos] = struct{}{}
					}

					// check if we already have data about this wall
					for step := int32(WallStep); ; step += 1 {
						iterations += 1

						moveDir := (forwardDir + uint8(4+turnDir)) % 4
						nextPos := curPos.InDir(moveDir, step)
						field, ok := m.mapStore.Map[nextPos]

						if !ok {
							curPos = nextPos
							state = StateFindTurn
							findTurnRotations = 0
							break
						}

						if field == MAP_WALL {
							curPos = curPos.InDir(moveDir, step-1)
							state = StateOnWall
							forwardDir = moveDir
							break
						}

						field, ok = m.mapStore.Map[nextPos.InDir(forwardDir, 1)]
						if !ok || field != MAP_WALL {
							curPos = nextPos
							state = StateFindTurn
							findTurnRotations = 0
							break
						}


						if _, ok = checkpoints[nextPos]; ok {
							log.Printf("found loop! stopping");
							return curPos, ok, nil
						}

						if step >= MaxStep {
							curPos = nextPos
							state = StateOnWall
							break
						}
					}

				case StateFindTurn:
					nextPos := curPos.InDir(forwardDir, 1)
					if findTurnRotations == 5 {
						wallField, ok := m.mapStore.Map[nextPos]
						if ok && wallField == MAP_WALL {
							log.Printf("find turn: found invalid wall at %v", nextPos)
							err := m.mapStore.Invalidate(nextPos)
							if err != nil {
								return curPos, true, err
							}
							curPos = nextPos
							state = StateFindTurn
							findTurnRotations = 0
							break
						}
					}

					if findTurnRotations >= 8 {
						log.Printf("loop in find turn: %v %v", curPos, findTurnRotations)

						return curPos, true, nil
					}
					curPos = nextPos
					state = StateTurn

				case StateTurn:
					forwardDir = (forwardDir + uint8(4-turnDir)) % 4
					state = StateFindTurn
					findTurnRotations += 1
				}

				// log.Printf("go %d %d state %v dir %d %d",
				// 	curPos.X, curPos.Y,
				// 	stateName[followerState],
				// 	maze.DIR_DX[forwardDir], maze.DIR_DY[forwardDir],
				// )
				err := m.s.SendState(PlayerState{
					Pos:  [3]int32{curPos.X * 1000, 20000, curPos.Y * 1000},
					Time: beat.Time + 1,
				})
				if err != nil {
					return curPos, true, err
				}

			}

			var teleport TeleportResponse
			if matched, err := teleport.Parse(packet); matched {
				if err != nil {
					return curPos, true, err
				}

				teleportPos := MapPos{teleport.Pos[0] / 1000, teleport.Pos[2] / 1000}
				m.mapStore.Add(teleportPos, MAP_FREE)


				if _, ok = checkpoints[curPos]; ok {
					log.Printf("found loop! stopping");
					return curPos, ok, nil
				}

				if teleportPos.InDir(forwardDir, 1) == curPos {
					m.mapStore.Add(curPos, MAP_WALL)
					curPos = teleportPos
					state = StateOnWall
					continue
				}

				if teleportPos.InDir((forwardDir+uint8(4 + turnDir))%4, 1) == curPos {
					m.mapStore.Add(curPos, MAP_WALL)
					curPos = teleportPos
					forwardDir = (forwardDir + uint8(4+turnDir)) % 4
					state = StateOnWall
					continue
				}

				dx := curPos.X - teleportPos.X
				dy := curPos.Y - teleportPos.Y
				if (dx > 10 || dx < -10) && (dy > 10 || dy < -10) {
					log.Printf("found proper teleport at %v", curPos)
					m.mapStore.Add(curPos, MAP_TELEPORT)
				}
				if dx != 0 && dy != 0 {
					log.Printf("unsolicted teleport from %v to %v in state %v", curPos, teleportPos, state)
					// revert and try to find a wall again
					curPos = teleportPos
					state = StateFindForward
					findForwardMoves = 0
					continue
				}

				d, delta := MajorDirFromTo(teleportPos, curPos)

				log.Printf("line teleport from %v to %v in state %s, dir %d %d %d delta %d %d %d",
					curPos, teleportPos,
					stateName[state],
					d, DIR_DX[d], DIR_DY[d],
					delta, dx, dy,
				)

				// invalidate the map along the line
				for step := int32(1); step <= delta; step += 1 {
					m.mapStore.Invalidate(teleportPos.InDir(d, step))
					m.mapStore.Invalidate(teleportPos.InDir(d, step).InDir((d+1)%4, 1))
				}

				state = StateFindTurn
				curPos = teleportPos
			}
		}
	}
}

func run(m *Mover) {
	defer close(m.doneSend)

	stateTimeout := time.NewTimer(3 * time.Second)
	defer stateTimeout.Stop()

requestPosition:
	for {
		curPos, err := m.s.GetPosition()
		if err != nil {
			log.Printf("error getting mover position: %v", err)
			return
		}

		for {
			log.Printf("mover waiting in position %v", curPos)
			select {

			case _, ok := <-m.Stop:
				if !ok {
					return
				}

			case target := <-m.StartStraight:
				log.Printf("start moving straight to %v", target)
				newPos, ok, err := runStraight(m, curPos, target)
				curPos = newPos
				if err != nil {
					log.Printf("error moving straight: %v", err)
				}

				m.mapStore.Flush()
				m.doneSend <- curPos
				if !ok {
					return
				}

			case dir := <-m.StartFollow:
				log.Printf("following wall in direction %v", dir)
				newPos, ok, err := runFollow(m, curPos, dir)
				curPos = newPos
				if err != nil {
					log.Printf("error following: %v", err)
				}

				m.mapStore.Flush()
				m.doneSend <- curPos
				if !ok {
					return
				}

			// force a new getposition call so that the server doesn't kick
			// us for being idle
			case _ = <-stateTimeout.C:
				stateTimeout.Reset(3 * time.Second)
				continue requestPosition
			}

			if !stateTimeout.Stop() {
				<-stateTimeout.C
			}
			stateTimeout.Reset(3 * time.Second)
		}
	}
}

func NewMover(s *Session, mapStore *MapStore) *Mover {
	var m Mover

	m.s = s
	m.mapStore = mapStore
	m.StartStraight = make(chan MapPos, 1)
	m.StartFollow = make(chan int8, 1)
	m.Stop = make(chan struct{}, 1)

	m.doneSend = make(chan MapPos, 1)
	m.Done = m.doneSend

	go func() {
		run(&m)
		log.Printf("shutdown mover")
	}()
	return &m
}

func (m *Mover) Close() {
	close(m.StartStraight)
	close(m.StartFollow)
	close(m.Stop)
}
