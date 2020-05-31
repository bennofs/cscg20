package main

import (
	"flag"
	"strconv"
	"encoding/binary"
	"image/color"
	"hash/fnv"
	"log"
	"fmt"
	"math"
	"os"
	"time"

	"five.name/cscg/maze"

	"github.com/faiface/pixel"
	"github.com/faiface/pixel/imdraw"
	"github.com/faiface/pixel/pixelgl"
	"github.com/faiface/pixel/text"
	"golang.org/x/image/colornames"
	"golang.org/x/image/font/basicfont"
)

type DrawnMap struct {
	highRes, lowRes *pixelgl.Canvas
}

func (d DrawnMap) Draw(t pixel.Target, zoom float64) {
	c := d.highRes
	if zoom < 0.7 {
		c = d.lowRes
	}
	c.Draw(t, pixel.IM.Moved(c.Bounds().Center()))
}

func drawMap(gameMap maze.GameMap) DrawnMap {
	imd := imdraw.New(nil)
	mapBounds := pixel.ZR
	for k, _ := range gameMap {
		x := float64(k.X)
		y := float64(k.Y)
		if x > mapBounds.Max.X {
			mapBounds.Max.X = x
		}
		if y > mapBounds.Max.Y {
			mapBounds.Max.Y = y
		}
		if x < mapBounds.Min.X {
			mapBounds.Min.X = x
		}
		if y < mapBounds.Min.Y {
			mapBounds.Min.Y = y
		}
	}

	var drawn DrawnMap
	drawn.highRes = pixelgl.NewCanvas(mapBounds)
	drawn.lowRes = pixelgl.NewCanvas(mapBounds)
	count := 0
	for k, v := range gameMap {
		if v == maze.MAP_FREE {
			imd.Color = colornames.Peru
		} else if v == maze.MAP_TELEPORT {
			imd.Color = colornames.Red
			pos := pixel.V(float64(k.X), float64(k.Y))
			imd.Push(pos)
			imd.Circle(10, 0)
			continue

		} else {
			imd.Color = colornames.Black
		}
		pos := pixel.V(float64(k.X), float64(k.Y))
		imd.Push(pos)
		imd.Push(pos.Add(pixel.V(1,1)))
		imd.Rectangle(0)
		count += 1
		if count > 1000 {
			imd.Draw(drawn.highRes)
			imd.Clear()
			count  = 0
		}
	}
	imd.Color = colornames.Orange
	imd.Push(pixel.V(2763, 2253))
	imd.Circle(10, 0)
	imd.Draw(drawn.highRes)

	imd.Clear()
	count = 0
	for k, v := range gameMap {
		if v == maze.MAP_FREE {
			continue
		} else if v == maze.MAP_TELEPORT {
			imd.Color = colornames.Red
			pos := pixel.V(float64(k.X), float64(k.Y))
			imd.Push(pos)
			imd.Circle(20, 0)
			continue
		} else {
			imd.Color = colornames.Black
		}
		pos := pixel.V(float64(k.X), float64(k.Y))
		imd.Push(pos)
		imd.Circle(7, 0)
		count += 1
		if count > 1000 {
			imd.Draw(drawn.lowRes)
			imd.Clear()
			count  = 0
		}
	}
	imd.Color = colornames.Orange
	imd.Push(pixel.V(2763, 2253))
	imd.Circle(10, 0)
	imd.Draw(drawn.lowRes)

	return drawn
}

func loadMap(fname string) (maze.GameMap, error) {
	f, err := os.Open(flag.Arg(0))
	if err != nil {
		return nil, err
	}

	gameMap, _, err := maze.ReadMap(f, true)
	f.Close()
	return gameMap, err
}

func periodic(interval time.Duration, action func(t time.Time)) chan struct {} {
	done := make(chan struct{}, 1)
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case t := <-ticker.C:
				action(t)
			case _, ok := <-done:
				if !ok {
					return
				}
			}
		}
	}()
	return done
}

func run() {
	initX := flag.Int("x", 2400, "initial x position of camera")
	initY := flag.Int("y", 2400, "initial y position of camera")
	trace := flag.Bool("trace", false, "trace, not just show, player positions")

	remote := flag.String("remote", "", "server to connect to. leave empty to start offline")
	username := flag.String("user", "observer", "username to authenticate as")
	password := flag.String("pass", "jasd98213", "password for login")

	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: rendermap [OPTIONS] MAPFILE\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	gameMap, err := loadMap(flag.Arg(0))
	if err != nil {
		log.Fatal(err)
	}

	reloadMap := make(chan DrawnMap, 1)
	defer close(periodic(time.Second * 1, func(_ time.Time) {
		gameMap, err := loadMap(flag.Arg(0))
		if err != nil {
			log.Printf("cannot reload map: %v", err)
		}
		reloadMap <- drawMap(gameMap)
	}))

	var client *maze.MazeConnection
	if *remote != "" {
		client, err = maze.Connect(*remote)
		if err != nil {
			log.Fatalf("connect: %v", err)
		}
		defer client.Close()

		client.RegisterTextHandlers()
		client.RegisterForceLogoutLogger()

		s, err := client.Login(*username, *password, false)
		if err != nil {
			log.Fatalf("login: %v", err)
		}

		start := time.Unix(0, 0)
		defer close(periodic(50 * time.Millisecond, func(t time.Time) {
			stamp := uint64(t.Sub(start).Milliseconds())
			s.SendHeartbeat(stamp)
			s.SendState(maze.PlayerState {
				Time: stamp,
				})
		}))

		log.Printf("connected to %s", *remote)
	}


	cfg := pixelgl.WindowConfig{
		Title:  "Pixel Rocks!",
		Bounds: pixel.R(0, 0, 1024, 768),
		VSync:  true,
	}
	win, err := pixelgl.NewWindow(cfg)
	if err != nil {
		panic(err)
	}

	var (
		camPos       = pixel.ZV
		camSpeed     = 500.0
		camZoom      = 1.0
		camZoomSpeed = 1.2
	)

	camPos.X += float64(*initX)
	camPos.Y += float64(*initY)
	log.Printf("initial cam pos: %d %d", *initX, *initY)

	imd := imdraw.New(nil)
	playerPosImd := imdraw.New(nil)
	last := time.Now()

	var xLines []float64
	var yLines []float64
	number := 0

	var packets chan []byte
	if client != nil {
		var done chan struct{}
		packets, done = client.PacketChannel()
		defer close(done)
	}
	players := make(map[uint32]maze.Player)

	basicAtlas := text.NewAtlas(basicfont.Face7x13, text.ASCII)
	drawnMap := drawMap(gameMap)
	var traceZoom float64

	for !win.Closed() {
		dt := time.Since(last).Seconds()
		last = time.Now()

		cam := pixel.IM.Scaled(camPos, camZoom).Moved(win.Bounds().Center().Sub(camPos))
		mousePos := cam.Unproject(win.MousePosition()).Sub(pixel.V(0.5,0.5))
		win.SetMatrix(cam)

		if win.Pressed(pixelgl.KeyLeft) {
			camPos.X -= camSpeed * dt
		}
		if win.Pressed(pixelgl.KeyRight) {
			camPos.X += camSpeed * dt
		}
		if win.Pressed(pixelgl.KeyDown) {
			camPos.Y -= camSpeed * dt
		}
		if win.Pressed(pixelgl.KeyUp) {
			camPos.Y += camSpeed * dt
		}
		if (win.JustPressed(pixelgl.KeyT)) {
			*trace = !*trace
		}
		if (win.JustPressed(pixelgl.KeyC)) {
			xLines = nil
			yLines = nil
		}
		if (win.JustPressed(pixelgl.KeyX)) {
			x := mousePos.X
			if number != 0 {
				x = float64(number)
			}

			xLines = append(xLines, x)
			number = 0
		}
		if (win.JustPressed(pixelgl.KeyZ)) {
			y := mousePos.Y
			if number != 0 {
				y = float64(number)
			}

			yLines = append(yLines, y)
			number = 0
		}

		newInput := win.Typed()
		if n, err := strconv.Atoi(newInput); err == nil {
			number = number * 10 + n
		} else if newInput != "" {
			number = 0
		}


		camZoom *= math.Pow(camZoomSpeed, win.MouseScroll().Y)

		if win.Pressed(pixelgl.MouseButton1) {
			camPos = camPos.Add(win.MousePreviousPosition().Sub(win.MousePosition()).Scaled(1 / camZoom))
		}

		win.Clear(colornames.White)
		drawnMap.Draw(win, camZoom)

		if !*trace {
			playerPosImd.Clear()
			traceZoom = camZoom
		}

		sum := [4]byte{}
		for _, p := range players {
			hasher := fnv.New32()
			binary.Write(hasher, binary.LittleEndian, p.Uid)
			hasher.Sum(sum[:0])
			playerPosImd.Color = color.RGBA { sum[0], sum[1], sum[2], 0xff }
			playerPosImd.Push(pixel.V(float64(p.State.Pos[0])/1000, float64(p.State.Pos[2])/1000))
			playerPosImd.Circle(7 * 1/traceZoom, 0)
		}
		playerPosImd.Draw(win)



		win.SetMatrix(pixel.IM)

		textPos := pixel.V(10, 10)
		imd.Clear()

		// draw hud
		imd.Color = pixel.Alpha(0.9)
		imd.Push(pixel.ZV)
		imd.Push(textPos.Add(pixel.V(300, 20)))
		imd.Rectangle(0)

		// draw helping lines
		imd.Color = colornames.Orange
		for _, x := range(xLines) {
			xScreen := cam.Project(pixel.V(x, 0)).X
			imd.Push(pixel.V(xScreen, win.Bounds().Min.Y))
			imd.Push(pixel.V(xScreen, win.Bounds().Max.Y))
			imd.Line(1)
		}


		imd.Color = colornames.Orangered
		for _, y := range(yLines) {
			yScreen := cam.Project(pixel.V(0, y)).Y
			imd.Push(pixel.V(win.Bounds().Min.X, yScreen))
			imd.Push(pixel.V(win.Bounds().Max.X, yScreen))
			imd.Line(1)
		}


		imd.Draw(win)

		text := text.New(textPos, basicAtlas)
		fmt.Fprintf(text, "x %04.0f y %04.0f number %04d", mousePos.X, mousePos.Y, number)
		text.DrawColorMask(win, pixel.IM, colornames.Indigo)

		select {
		case packet := <-packets:
			var m maze.StateResponse
			matched, err := m.Parse(packet)
			if err != nil {
				log.Fatal(err)
			}

			if matched {
				for _, p := range(m.Players) {
					players[p.Uid] = p
				}
			}
		case newMap := <-reloadMap:
			drawnMap = newMap
		default:
			break
		}

		win.Update()
	}
}

func main() {
	pixelgl.Run(run)
}
