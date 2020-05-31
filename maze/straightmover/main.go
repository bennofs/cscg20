package main

import (
	"log"
	"time"
	"fmt"

	"five.name/cscg/maze"
)

type Route struct {
	Points []maze.MapPos
}

func main() {
	conn, err := maze.Connect("maze.liveoverflow.com:1337")
	if err != nil {
		log.Fatalf("connect: %v", err)
	}

	conn.RegisterTeleportLogger();
	conn.RegisterTextHandlers();

	var teleport maze.TeleportResponse
	teleportc := conn.WaitForMessage(&teleport)

	var login maze.LoginRequest
	login.Prepare("foobar", fmt.Sprintf("notsecret%v", time.Now().UnixNano()))
	conn.SendMessage(&login);

	// wait for the initial teleport telling us where we start
	<-teleportc
	log.Printf("%+v", teleport)

	Pos := teleport.Pos
	step := int32(100002)
	t := uint64(1);
	teleportc = conn.WaitForMessage(&teleport) // wait for new teleports
	for {
		Pos[0] += step
		stateMsg := maze.StateRequest {
			Secret: login.Secret,
			MyState: maze.PlayerState {
				Time: t,
				Pos: Pos,
			},
		}
		conn.SendMessage(&stateMsg)
		time.Sleep(50 * time.Millisecond)
		t = t + 10000000


		select {
		case <-teleportc:
			Pos = teleport.Pos
			if step > 1 {
				step = step - 1
			}
			log.Printf("reduced step to %v", step)
			teleportc = conn.WaitForMessage(&teleport)
		default:
		}
	}
}
