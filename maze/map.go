package maze

import (
	"bufio"
	"encoding/binary"
	"io"
	"log"
	"os"
)

const (
	MAP_FREE = int8(iota)
	MAP_WALL
	MAP_TELEPORT
	MAP_INVALIDATE
)

var (
	DIR_DX = [4]int32{1, 0, -1, 0}
	DIR_DY = [4]int32{0, 1, 0, -1}

	Checkpoints = [...]MapPos{
		MapPos{int32(2039), int32(1939)},
		MapPos{int32(1807), int32(1790)},
		MapPos{int32(1730), int32(2084)},
		MapPos{int32(1880), int32(2333)},
		MapPos{int32(1652), int32(2322)},
		MapPos{int32(1507), int32(1862)},
		MapPos{int32(1800), int32(1621)},
		MapPos{int32(1651), int32(1185)},
		MapPos{int32(1213), int32(966)},
		MapPos{int32(1200), int32(1260)},
		MapPos{int32(1120), int32(1940)},
		MapPos{int32(756), int32(2087)},
		MapPos{int32(608), int32(2090)},
	}
)

type MapPos struct {
	X, Y int32
}

func MapPosFromGame(p [3]int32) MapPos {
	return MapPos{p[0] / 1000, p[2] / 1000}
}

func (self MapPos) Rel(dx, dy int32) MapPos {
	return MapPos{self.X + dx, self.Y + dy}
}

func (self MapPos) InDir(d uint8, step int32) MapPos {
	return self.Rel(DIR_DX[d]*step, DIR_DY[d]*step)
}

func MajorDirFromTo(from, to MapPos) (uint8, int32) {
	dx := to.X - from.X
	dy := to.Y - from.Y
	var bestDist int32
	var bestDir uint8
	for d := uint8(0); d < 4; d += 1 {
		dist := DIR_DX[d]*dx + DIR_DY[d]*dy
		if dist > bestDist {
			bestDist = dist
			bestDir = d
		}
	}
	return bestDir, bestDist
}

func Int32Dist(a, b int32) int32 {
	if a < b {
		return b - a
	} else {
		return a - b
	}
}

func ManhattanDist(a, b MapPos) int32 {
	return Int32Dist(a.X, b.X) + Int32Dist(a.Y, b.Y)
}

type GameMap map[MapPos]int8

func (m GameMap) NextPos(curPos MapPos) MapPos {
	explored := make(map[MapPos]struct{})
	frontier := make(map[MapPos]uint8)

	// build initial frontier
	for i := uint8(0); i < 4; i += 1 {
		p := curPos.InDir(i, 1)
		a, aOk := m[p]
		if !aOk {
			return p
		}
		if a != MAP_WALL {
			frontier[p] = i
		}
	}
	explored[curPos] = struct{}{}

	// update frontier until we find unvisited
	for {
		nextFrontier := make(map[MapPos]uint8)

		for pos, i := range frontier {
			for n := int8(0); n < 4; n += 1 {
				npos := pos.InDir(i, 1)
				state, ok := m[npos]
				if !ok {
					return curPos.InDir(i, 1)
				}
				if state != MAP_WALL {
					_, alreadyExplored := explored[npos]
					if !alreadyExplored {
						nextFrontier[npos] = i
					}
				}
			}
			explored[pos] = struct{}{}
		}

		frontier = nextFrontier
	}
}

type LogEntry struct {
	Pos   MapPos
	State int8
}

type MapStore struct {
	f           *os.File
	writer      *bufio.Writer
	maxWrites   int
	lastSaveLen uint64
	entryCount  uint64
	Map         GameMap
}

func ReadMap(f *os.File, allowPartial bool) (GameMap, uint64, error) {
	m := make(GameMap)
	var count uint64
	reader := bufio.NewReader(f)
	err := binary.Read(reader, binary.LittleEndian, &count)
	if err != nil {
		return m, 0, err
	}
	for i := uint64(0); i < count; i += 1 {
		var entry LogEntry
		err := binary.Read(reader, binary.LittleEndian, &entry)
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, 0, err
		}
		if entry.State == MAP_INVALIDATE {
			delete(m, entry.Pos)
		} else {
			m[entry.Pos] = entry.State
		}
	}
	log.Printf("opened map with %d entries", count)
	return m, count, nil
}

func OpenMapStore(fname string, maxWrites int) (*MapStore, error) {
	f, err := os.OpenFile(fname, os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		return nil, err
	}

	var store MapStore
	store.Map, store.entryCount, err = ReadMap(f, false)
	if err == io.EOF {
		store.entryCount = 0
		store.Map = make(GameMap)
		binary.Write(f, binary.LittleEndian, store.entryCount)
		err = nil
	}
	if err != nil {
		return nil, err
	}
	store.maxWrites = maxWrites
	store.f = f
	store.lastSaveLen = store.entryCount
	store.writer = bufio.NewWriter(f)

	return &store, nil
}

func (s *MapStore) Flush() error {
	err := s.writer.Flush()
	if err != nil {
		return err
	}

	curPos, err := s.f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}

	_, err = s.f.Seek(0, io.SeekStart)
	if err != nil {
		return err
	}

	err = binary.Write(s.f, binary.LittleEndian, s.entryCount)
	if err != nil {
		return err
	}

	_, err = s.f.Seek(curPos, io.SeekStart)

	log.Printf("map store flushed: %d %d", s.entryCount, curPos)
	return err
}

func (s *MapStore) Close() error {
	log.Printf("close map")
	err := s.Flush()
	if err != nil {
		log.Printf("close map err: %v", err)
		return err
	}
	return s.f.Close()
}

func (s *MapStore) Invalidate(p MapPos) error {
	log.Printf("[INVALIDATE] map pos %v", p)
	delete(s.Map, p)

	err := binary.Write(s.writer, binary.LittleEndian, &LogEntry{p, MAP_INVALIDATE})
	if err != nil {
		return err
	}
	s.entryCount += 1
	if s.entryCount > s.lastSaveLen+uint64(s.maxWrites) {
		err := s.Flush()
		if err != nil {
			return err
		}
		s.lastSaveLen = s.entryCount
	}

	return nil
}

func (s *MapStore) Add(p MapPos, state int8) error {
	if v, existing := s.Map[p]; existing {
		if state != MAP_FREE || state == v {
			return nil
		}
	}

	s.Map[p] = state
	err := binary.Write(s.writer, binary.LittleEndian, &LogEntry{p, state})
	if err != nil {
		return err
	}
	s.entryCount += 1
	if s.entryCount > s.lastSaveLen+uint64(s.maxWrites) {
		err := s.Flush()
		if err != nil {
			return err
		}
		s.lastSaveLen = s.entryCount
	}
	return nil
}
