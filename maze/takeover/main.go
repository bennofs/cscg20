package main

import (
	"five.name/cscg/maze"
	"fmt"
	"io"
	"log"
)

func main() {
	conn, newClient, err := maze.ListenForTakeover(":1234")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	c := <-newClient

	go func() {
		for packet := range(c.Packets) {
			var state maze.StateRequest
			if matched, err := state.Parse(packet); matched {
				if err != nil {
					log.Printf("state parse err: %v", err)
				}

				log.Printf("pos: %d %d", state.MyState.Pos[0]/1000, state.MyState.Pos[2]/1000)
			}
		}
	}()

	for {
		var x, y, z int32
		n, err := fmt.Scanf("%d %d %d\n", &x, &y, &z)
		if err == io.EOF {
			conn.Close()
			return
		}
		if n != 3 {
			log.Printf("invalid input: %d", n)
			continue
		}

		conn.WriteTo(maze.EncodeMessage(&maze.TeleportResponse{
			Pos:     [3]int32{x * 1000, 20000 * z, y * 1000},
			Instant: 1,
		}), c.Addr)
	}
}
