package main

import (
	"fmt"
	"os"
	"log"
	"flag"

	"five.name/cscg/maze"
)

func main() {
	flag.Parse()

	if len(flag.Args()) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mergemap <BASE> TOADD...")
		os.Exit(1)
	}


	mapStore, err := maze.OpenMapStore(flag.Arg(0), 10000)
	defer mapStore.Close()
	if err != nil {
		log.Fatalf("open base store: %v", err)
	}

	for _, toMerge := range(flag.Args()[1:]) {
		f, err := os.Open(toMerge)
		if err != nil {
			log.Fatalf("cannot open %s: %v", toMerge, err)
		}

		gameMap, _, err := maze.ReadMap(f, true)
		if err != nil {
			log.Fatalf("cannot read %s: %v", toMerge, err)
		}

		for k,v := range(gameMap) {
			mapStore.Add(k, v)
		}

		f.Close()
	}
}
