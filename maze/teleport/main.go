package main

import (
	"flag"
	"strconv"
	"log"
	"five.name/cscg/maze"
)

func main() {
	flag.Parse()
	x, _ := strconv.Atoi(flag.Arg(0))
	y, _ := strconv.Atoi(flag.Arg(1))
	z, _ := strconv.Atoi(flag.Arg(2))
	log.Printf("teleport to %d %d %d", x, y, z)

	teleport := &maze.TeleportResponse {
	Instant: 1,
		Pos: [3]int32{int32(x),int32(y),int32(z)},
	}

	c, _ := maze.Connect("127.0.0.1:2345")
	c.SendMessage(teleport)
}
