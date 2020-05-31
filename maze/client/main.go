package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"image/color"
	"io/ioutil"
	"log"
	"math"
	"math/rand"
	"os"
	"strconv"
	"time"

	"five.name/cscg/maze"

	"github.com/faiface/pixel"
	"github.com/faiface/pixel/imdraw"
	"github.com/faiface/pixel/pixelgl"
	"github.com/faiface/pixel/text"
	"golang.org/x/image/colornames"
	"golang.org/x/image/font/basicfont"
)

const (
	MOVER_IDLE = iota
	MOVER_TARGET
	MOVER_FOLLOW
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
		imd.Push(pos.Add(pixel.V(1, 1)))
		imd.Rectangle(0)
		count += 1
		if count > 1000 {
			imd.Draw(drawn.highRes)
			imd.Clear()
			count = 0
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
			count = 0
		}
	}
	imd.Color = colornames.Orange
	imd.Push(pixel.V(2763, 2253))
	imd.Circle(10, 0)
	imd.Draw(drawn.lowRes)

	return drawn
}

func loadMap(fname string) (maze.GameMap, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}

	gameMap, _, err := maze.ReadMap(f, true)
	gameMap[maze.MapPos{int32(2699), int32(2572)}] = maze.MAP_TELEPORT
	gameMap[maze.MapPos{int32(2964), int32(2319)}] = maze.MAP_TELEPORT
	gameMap[maze.MapPos{int32(2751), int32(2206)}] = maze.MAP_TELEPORT
	gameMap[maze.MapPos{int32(2373), int32(2375)}] = maze.MAP_TELEPORT
	return gameMap, err
}

func periodic(interval time.Duration, action func(t time.Time)) chan struct{} {
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

func spawnController(remote, userActive, passActive, mapFile string, interval time.Duration, maxWrites int) (*maze.Mover, uint32, error) {
	if userActive == "" {
		return nil, 0, nil
	}

	mapStore, err := maze.OpenMapStore("map.bin", maxWrites)
	if err != nil {
		return nil, 0, fmt.Errorf("open map store: %v", err)
	}

	conn, err := maze.Connect(remote)
	if err != nil {
		return nil, 0, fmt.Errorf("connect: %v", err)
	}

	s, err := conn.Login(userActive, passActive, true)
	if err != nil {
		return nil, 0, fmt.Errorf("login: %v", err)
	}

	s.Conn.RegisterTextHandlers()
	s.Conn.RegisterTeleportLogger()
	s.Conn.RegisterForceLogoutLogger()
	s.Conn.RegisterCheckpointLogger()

	mover := maze.NewMover(s, mapStore)
	pacemaker := s.StartPacemaker(interval, 0, 1000000)

	done := make(chan maze.MapPos, 1)
	origDone := mover.Done
	go func() {
		defer s.Close()
		defer close(pacemaker)
		defer mapStore.Close()
		defer close(done)

		for d := range origDone {
			done <- d
		}
	}()

	mover.Done = done
	return mover, s.Login.Uid, nil
}

type Route struct {
	Points []maze.MapPos
}

func stepInDir(curPos, target maze.MapPos) maze.MapPos {
	dx := (target.X - curPos.X)
	dy := (target.Y - curPos.Y)

	if dx*dx+dy*dy > maze.MaxStep*maze.MaxStep {
		norm := math.Sqrt(float64(dx*dx + dy*dy))
		dx = dx * maze.MaxStep / int32(norm+1)
		dy = dy * maze.MaxStep / int32(norm+1)
	}

	curPos.X += dx;
	curPos.Y += dy;

	return curPos;
}

func run() {
	initX := flag.Int("x", 2400, "initial x position of camera")
	initY := flag.Int("y", 2400, "initial y position of camera")
	trace := flag.Bool("trace", false, "trace, not just show, player positions")

	remote := flag.String("remote", "", "server to connect to. leave empty to start offline")
	userObs := flag.String("obsuser", "observer", "username for the observer")
	passObs := flag.String("obspass", "jasd98213", "password for the observer")
	userActive := flag.String("user", "", "username for active control. leave empty to disable active")
	passActive := flag.String("pass", "jae8aH5u", "password for active user")
	intervalArg := flag.Duration("interval", 50*time.Millisecond, "heartbeat interval for active user ")
	maxWrites := flag.Int("maxwrites", 30, "save a snapshot of the map after this many writes")
	mapFileName := flag.String("map", "map.bin", "name of the file that stores map data")
	routeFileName := flag.String("route", "route.json", "save file for a route")
	flag.Parse()

	if *userActive != "" && *remote == "" {
		log.Fatalf("-remote argument is required to connect an active client")
	}

	mover, moverUid, err := spawnController(*remote, *userActive, *passActive, *mapFileName, *intervalArg, *maxWrites)
	if err != nil {
		log.Fatalf("start active controller: %v", err)
	}
	if mover != nil {
		defer mover.Close()
	}

	gameMap, err := loadMap(*mapFileName)
	if err != nil {
		log.Fatalf("load map %s: %v", *mapFileName, err)
	}

	reloadMap := make(chan DrawnMap, 1)
	defer close(periodic(time.Second*1, func(_ time.Time) {
		gameMap, err := loadMap(*mapFileName)
		if err != nil {
			log.Printf("cannot reload map: %v", err)
		}
		for _, toMerge := range flag.Args() {
			otherMap, err := loadMap(toMerge)
			if err != nil {
				log.Printf("cannot merge map: %v", err)
			}
			for k, v := range otherMap {
				_, ok := gameMap[k]
				if !ok {
					gameMap[k] = v
				}
			}

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

		s, err := client.Login(*userObs, *passObs, false)
		if err != nil {
			log.Fatalf("login: %v", err)
		}

		start := time.Unix(0, 0)
		defer close(periodic(50*time.Millisecond, func(t time.Time) {
			stamp := uint64(t.Sub(start).Milliseconds())
			s.SendHeartbeat(stamp)
			s.SendState(maze.PlayerState{
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

	var targetQueue []maze.MapPos
	var prevTargetQueue []maze.MapPos
	selectedTarget := -1
	moverState := MOVER_IDLE
	var moverNextTarget maze.MapPos
	moverFollowRepeat := false
	moverProcessQueue := mover != nil
	moverRollback := false
	lineFromLast := false

	for !win.Closed() {
		dt := time.Since(last).Seconds()
		last = time.Now()

		cam := pixel.IM.Scaled(camPos, camZoom).Moved(win.Bounds().Center().Sub(camPos))
		mousePos := cam.Unproject(win.MousePosition()).Sub(pixel.V(0.5, 0.5))
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
		if win.JustPressed(pixelgl.KeyT) {
			*trace = !*trace
		}
		if win.JustPressed(pixelgl.KeyO) && *routeFileName != "" {
			f, err := os.Open(*routeFileName)
			if err != nil {
				log.Fatalf("open route file: %v", err)
			}

			var route Route
			err = json.NewDecoder(f).Decode(&route)
			if err != nil {
				log.Fatalf("deserialize route: %v", err)
			}
			moverProcessQueue = false
			targetQueue = nil
			for i, point := range(route.Points) {
				if i == 0 {
					targetQueue = append(targetQueue, point);
					continue
				}

				cur := targetQueue[len(targetQueue) - 1];
				for cur != point {
					cur = stepInDir(cur, point);
					targetQueue = append(targetQueue, cur);
				}
			}
		}
		if win.JustPressed(pixelgl.KeyP) && *routeFileName != "" {
			encoded, err := json.Marshal(&Route{targetQueue})
			if err != nil {
				log.Fatalf("encode route: %v", err)
			}

			err = ioutil.WriteFile(*routeFileName, encoded, 0755)
			if err != nil {
				log.Fatalf("write route file: %v", err)
			}
		}
		if win.JustPressed(pixelgl.KeyU) && len(targetQueue) == 0 {
			moverRollback = true
			moverProcessQueue = true
			for i := len(prevTargetQueue) - 1; i >= 0; i -= 1 {
				targetQueue = append(targetQueue, prevTargetQueue[i])
			}
		}
		if win.JustPressed(pixelgl.KeySpace) {
			moverProcessQueue = !moverProcessQueue
			if moverProcessQueue && len(targetQueue) > 0 {
				prevTargetQueue = append([]maze.MapPos(nil), targetQueue...)
			}
		}
		if win.JustPressed(pixelgl.KeyC) {
			xLines = nil
			yLines = nil
		}
		if win.JustPressed(pixelgl.KeyV) {
			lineFromLast = !lineFromLast;
		}
		if win.JustPressed(pixelgl.KeyX) {
			x := mousePos.X
			if number != 0 {
				x = float64(number)
			}

			xLines = append(xLines, x)
			number = 0
		}
		if win.JustPressed(pixelgl.KeyZ) {
			y := mousePos.Y
			if number != 0 {
				y = float64(number)
			}

			yLines = append(yLines, y)
			number = 0
		}
		if win.JustPressed(pixelgl.KeyBackspace) {
			if len(targetQueue) == 0 {
				if moverState == MOVER_TARGET {
					mover.Stop <- struct{}{}
				}
			} else {
				if selectedTarget != -1 && selectedTarget < len(targetQueue) {
					targetQueue = append(targetQueue[:selectedTarget], targetQueue[selectedTarget + 1:]...)
				} else {
					l := len(targetQueue) - 1
					targetQueue = targetQueue[:l]
				}
			}
		}

		if win.JustPressed(pixelgl.KeyEscape) {
			moverFollowRepeat = false
			selectedTarget = -1
			if moverState != MOVER_IDLE {
				mover.Stop <- struct{}{}
			}
		}

		moverDirection := int8(4)
		if win.JustPressed(pixelgl.KeyD) {
			moverDirection = 0
		}
		if win.JustPressed(pixelgl.KeyW) {
			moverDirection = 1
		}
		if win.JustPressed(pixelgl.KeyA) {
			moverDirection = 2
		}
		if win.JustPressed(pixelgl.KeyS) {
			moverDirection = 3
		}
		if moverDirection != 4 && moverState == MOVER_IDLE {
			if win.Pressed(pixelgl.KeyLeftShift) || win.Pressed(pixelgl.KeyRightShift) {
				moverDirection -= 4
			}

			moverFollowRepeat = true
			mover.StartFollow <- moverDirection
			moverState = MOVER_FOLLOW
		}

		if win.JustPressed(pixelgl.MouseButton2) {
			target := maze.MapPos{int32(mousePos.X), int32(mousePos.Y)}
			prevTargetIdx := -1
			if selectedTarget > 0 {
				prevTargetIdx = selectedTarget - 1;
			} else if selectedTarget == -1 {
				prevTargetIdx = len(targetQueue) - 1;
			}
			if prevTargetIdx != -1 {
				target = stepInDir(targetQueue[prevTargetIdx], target)
			}
			if selectedTarget != -1 && selectedTarget < len(targetQueue) {
				targetQueue = append(targetQueue, maze.MapPos{})
				copy(targetQueue[selectedTarget+1:], targetQueue[selectedTarget:])
				targetQueue[selectedTarget] = target
			} else {
				targetQueue = append(targetQueue, target)
			}
			selectedTarget = -1
		}

		// process queue
		if moverState == MOVER_IDLE && mover != nil {
			if moverProcessQueue && len(targetQueue) > 0 {
				moverFollowRepeat = false
				moverNextTarget = targetQueue[0]
				mover.StartStraight <- targetQueue[0]
				targetQueue = targetQueue[1:]
				moverState = MOVER_TARGET
			} else if moverFollowRepeat {
				mover.StartFollow <- int8(rand.Intn(8) - 4)
				moverState = MOVER_FOLLOW
			} else if moverProcessQueue && len(targetQueue) == 0 && moverRollback {
				targetQueue = append([]maze.MapPos(nil), prevTargetQueue...)
				moverProcessQueue = false
				moverRollback = false
			}
		}

		newInput := win.Typed()
		if n, err := strconv.Atoi(newInput); err == nil {
			number = number*10 + n
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
			playerPosImd.Color = color.RGBA{sum[0], sum[1], sum[2], 0xff}
			playerPosImd.Push(pixel.V(float64(p.State.Pos[0])/1000, float64(p.State.Pos[2])/1000))
			playerPosImd.Circle(7*1/traceZoom, 0)
		}
		playerPosImd.Draw(win)

		imd.Clear()
		decay := math.Pow(0.5, 1/float64(len(targetQueue)))
		targetRadius := 7/camZoom
		for i, target := range targetQueue {
			alpha := pixel.Alpha(math.Pow(decay, float64(i)))
			imd.Color = alpha.Mul(pixel.ToRGBA(colornames.Darkorange))

			dx := mousePos.X - float64(target.X)
			dy := mousePos.Y - float64(target.Y)
			if win.Pressed(pixelgl.MouseButton1) && dx*dx + dy*dy <= targetRadius {
				selectedTarget = i
			}

			if i == selectedTarget {
				imd.Color = colornames.Red
			}


			imd.Push(pixel.V(float64(target.X), float64(target.Y)))
			imd.Circle(targetRadius, 0)

			if i + 1 < len(targetQueue) {
				nextTarget := targetQueue[i + 1]
				imd.Push(pixel.V(float64(target.X), float64(target.Y)))

				alpha := pixel.Alpha(math.Pow(decay, float64(i + 1)))
				imd.Color = alpha.Mul(pixel.ToRGBA(colornames.Darkorange))
				imd.Push(pixel.V(float64(nextTarget.X), float64(nextTarget.Y)))
				imd.Line(1)
			}
		}

		var refPos []maze.MapPos
		if selectedTarget != -1 && selectedTarget < len(targetQueue) {
			refPos = append(refPos, targetQueue[selectedTarget])
			if selectedTarget - 1 >= 0 {
				refPos = append(refPos, targetQueue[selectedTarget - 1])
			}
		} else {
			if moverState == MOVER_TARGET {
				imd.Color = colornames.Firebrick
				imd.Push(pixel.V(float64(moverNextTarget.X), float64(moverNextTarget.Y)))
				playerPosImd.Circle(7*1/traceZoom, 0)
				refPos = append(refPos, moverNextTarget)
			} else if len(targetQueue) != 0 {
				refPos = append(refPos, targetQueue[len(targetQueue)-1])
			} else if (!moverProcessQueue && len(targetQueue) == 0) {
				if p, ok := players[moverUid]; ok {
					pos := maze.MapPosFromGame(p.State.Pos)
					refPos = append(refPos, pos)
				}
			} else if lineFromLast {
				refPos = append(refPos, moverNextTarget)
			}
		}
		for _, p := range(refPos) {
			imd.Color = pixel.ToRGBA(colornames.Gray).Mul(pixel.Alpha(0.7))
			imd.Push(pixel.V(float64(p.X), float64(p.Y)))
			imd.Push(mousePos)
			imd.Line(2)
			target := maze.MapPos{int32(mousePos.X), int32(mousePos.Y)}
			next := stepInDir(p, target);
			imd.Push(pixel.V(float64(next.X), float64(next.Y)));
			imd.Circle(targetRadius, 0);
		}

		imd.Color = pixel.ToRGBA(colornames.Chartreuse).Mul(pixel.Alpha(0.2))
		for _, checkpoint := range maze.Checkpoints {
			imd.Push(pixel.V(float64(checkpoint.X), float64(checkpoint.Y)))
			imd.Circle(25, 0)
		}
		imd.Draw(win)

		win.SetMatrix(pixel.IM)

		textPos := pixel.V(10, 10)
		imd.Clear()

		// draw helping lines
		imd.Color = colornames.Orange
		for _, x := range xLines {
			xScreen := cam.Project(pixel.V(x, 0)).X
			imd.Push(pixel.V(xScreen, win.Bounds().Min.Y))
			imd.Push(pixel.V(xScreen, win.Bounds().Max.Y))
			imd.Line(1)
		}

		// draw hud
		imd.Color = pixel.Alpha(0.9)
		imd.Push(pixel.ZV)
		imd.Push(textPos.Add(pixel.V(500, 20)))
		imd.Rectangle(0)

		imd.Color = colornames.Orangered
		for _, y := range yLines {
			yScreen := cam.Project(pixel.V(0, y)).Y
			imd.Push(pixel.V(win.Bounds().Min.X, yScreen))
			imd.Push(pixel.V(win.Bounds().Max.X, yScreen))
			imd.Line(1)
		}

		imd.Draw(win)

		text := text.New(textPos, basicAtlas)
		fmt.Fprintf(text, "x %04.0f y %04.0f number %04d", mousePos.X, mousePos.Y, number)
		if len(targetQueue) != 0 || moverState == MOVER_TARGET {
			fmt.Fprintf(text, " targets %d", len(targetQueue))
		}
		if moverState == MOVER_FOLLOW {
			fmt.Fprintf(text, " follow")
		}
		if !moverProcessQueue {
			fmt.Fprintf(text, " paused")
		}
		text.DrawColorMask(win, pixel.IM, colornames.Indigo)

		var moverDone <-chan maze.MapPos
		if mover != nil {
			moverDone = mover.Done
		}

		select {

		case pos := <-moverDone:
			if p, ok := players[moverUid]; ok {
				p.State.Pos[0] = pos.X * 1000
				p.State.Pos[2] = pos.Y * 1000
				players[moverUid] = p
			}
			moverState = MOVER_IDLE

		case packet := <-packets:
			var m maze.StateResponse
			matched, err := m.Parse(packet)
			if err != nil {
				log.Fatal(err)
			}

			if matched {
				for _, p := range m.Players {
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
