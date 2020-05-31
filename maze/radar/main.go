package main

import (
	"flag"
	"encoding/binary"
	"hash/fnv"
	"image"
	"image/color"
	"log"
	"math"
	"os"
	"time"

	"five.name/cscg/maze"

	"github.com/faiface/pixel"
	"github.com/faiface/pixel/imdraw"
	"github.com/faiface/pixel/pixelgl"
	"golang.org/x/image/colornames"
)

func loadPicture(path string) (pixel.Picture, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	img, _, err := image.Decode(file)
	if err != nil {
		return nil, err
	}
	return pixel.PictureDataFromImage(img), nil
}

func run() {
	initX := flag.Int("x", 2400, "initial x position of camera")
	initY := flag.Int("y", 2400, "initial y position of camera")
	s, _, err := maze.CreateSession(false)
	if err != nil {
		log.Fatal(err)
	}

	done := s.StartPacemaker(500*time.Millisecond, 0, 1)
	defer close(done)

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

	imd := imdraw.New(nil)
	packets, done := s.Conn.PacketChannel()
	start := time.Now()
	last := time.Now()
	lastPacket := time.Now()

	camPos.X = float64(*initX)
	camPos.Y = float64(*initY)

	for !win.Closed() {
		dt := time.Since(last).Seconds()
		last = time.Now()

		if last.Sub(lastPacket).Seconds() > 2 {
			state := maze.PlayerState{
				Time: uint64(last.Sub(start).Seconds()),
			}
			s.SendState(state)
			lastPacket = last
		}

		cam := pixel.IM.Scaled(camPos, camZoom).Moved(win.Bounds().Center().Sub(camPos))
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
		camZoom *= math.Pow(camZoomSpeed, win.MouseScroll().Y)

		if (win.Pressed(pixelgl.MouseButton1)) {
			camPos = camPos.Add(win.MousePreviousPosition().Sub(win.MousePosition()).Scaled(1/camZoom))
		}

		win.Clear(colornames.White)
		imd.Draw(win)
		win.Update()

		select {
		case packet := <-packets:
			var m maze.StateResponse
			matched, err := m.Parse(packet)
			if err != nil {
				log.Fatal(err)
			}

			if matched {
				sum := [4]byte{}
				for _, p := range m.Players {
					hasher := fnv.New32()
					binary.Write(hasher, binary.LittleEndian, p.Uid)
					hasher.Sum(sum[:0])
					imd.Color = color.RGBA { sum[0], sum[1], sum[2], 0xff }
					imd.Push(pixel.V(float64(p.State.Pos[0])/1000, float64(p.State.Pos[2])/1000))
					imd.Circle(5, 0)
				}
			}
		default:
			break
		}
	}
}

func main() {
	pixelgl.Run(run)
}
