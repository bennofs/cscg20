package maze

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
)

const (
	maxBufferSize = 1024
)

func DecodeCipher(out, data []byte) []byte {
	curkey := data[0]
	key := data[1]

	for idx := 0; idx+2 < len(data); idx += 1 {
		out[idx] = data[idx+2] ^ curkey
		curkey = curkey + key + byte((uint16(key)+uint16(curkey))/0xff)
	}

	return out[:len(data)-2]
}

func EncodeCipher(out, data []byte) []byte {
	curkey := out[0]
	key := out[1]

	for idx := 0; idx+2 < len(data); idx += 1 {
		out[idx+2] = data[idx] ^ curkey
		curkey = curkey + key + byte((uint16(key)+uint16(curkey))/0xff)
	}

	return out[:len(data)+2]
}

type MessageHandler func([]byte) bool
type MazeConnection struct {
	conn io.ReadWriteCloser

	addHandler chan MessageHandler
}

func (m *MazeConnection) Close() error {
	log.Printf("shutdown maze connection")
	close(m.addHandler)
	return m.conn.Close()
}

func (m *MazeConnection) startReader() {
	m.addHandler = make(chan MessageHandler, 100)
	go func() {
		var handlers []MessageHandler
		buffer := make([]byte, 512)
		for {
			n, err := m.conn.Read(buffer)

			// check if channel has been closed (and the stream as well)
			// before checking for errors
			for done := false; !done; {
				select {
				case handler, ok := <-m.addHandler:
					if !ok {
						return
					}
					handlers = append(handlers, handler)
				default:
					done = true
				}
			}

			if err != nil {
				log.Fatal(err)
			}

			DecodeCipher(buffer, buffer[:n])

			for idx := 0; idx < len(handlers); {
				remove := handlers[idx](buffer[:n-2])
				if remove {
					lastIdx := len(handlers) - 1
					handlers[idx] = handlers[lastIdx]
					handlers[lastIdx] = nil
					handlers = handlers[:lastIdx]
				} else {
					idx += 1
				}
			}
		}
	}()
}

func WrapMaze(conn io.ReadWriteCloser) *MazeConnection {
	m := MazeConnection{
		conn: conn,
	}
	m.startReader()
	return &m
}

func Connect(remote string) (m *MazeConnection, err error) {
	m = new(MazeConnection)

	raddr, err := net.ResolveUDPAddr("udp", remote)
	if err != nil {
		return
	}

	m.conn, err = net.DialUDP("udp", nil, raddr)
	m.startReader()

	return
}

func (m *MazeConnection) SendHex(data string) error {
	buf, err := hex.DecodeString(data)
	if err != nil {
		return err
	}
	_, err = m.Write(buf)
	return err
}

func (m *MazeConnection) Write(data []byte) (int, error) {
	out := make([]byte, len(data)+2)
	n, err := m.conn.Write(EncodeCipher(out, data))
	n -= 2
	if n < 0 {
		n = 0
	}
	return n, err
}

func (m *MazeConnection) WriteRaw(data []byte) (int, error) {
	return m.conn.Write(data)
}

func (m *MazeConnection) SendMessage(msg NetMessage) error {
	var out bytes.Buffer
	out.Write([]byte{0, 0})
	err := msg.Serialize(&out)
	if err != nil {
		return err
	}
	_, err = m.conn.Write(out.Bytes())
	return err
}

func (m *MazeConnection) AddHandler(handler MessageHandler) {
	m.addHandler <- handler
}

func (m *MazeConnection) ProcessUntil(handler MessageHandler) {
	done := make(chan struct{}, 1)
	m.AddHandler(func (payload []byte) bool {
		isDone := handler(payload)
		if isDone {
			close(done)
		}
		return isDone
	})
	_, _ = <-done
}

func (m *MazeConnection) PacketChannel() (chan []byte, chan struct{}) {
	out := make(chan []byte, 100)
	done := make(chan struct{}, 1)
	m.AddHandler(func(payload []byte) bool {
		for {
			select {
			case _, ok := <-done:
				if !ok {
					return true
				}
			// make sure to copy the buffer here,
			// as it may be reused when we return
			case out <- append([]byte(nil), payload...):
				return false
			}
		}
	})
	return out, done
}

func (m *MazeConnection) WaitForMessage(msg NetMessage) chan error {
	c := make(chan error, 1)
	m.AddHandler(func(payload []byte) bool {
		matched, err := msg.Parse(payload)
		if !matched {
			return false
		}

		c <- err
		close(c)
		return true
	})
	return c
}

type NetMessage interface {
	Parse(payload []byte) (bool, error)
	Serialize(w io.Writer) error
}

type LoginResponse struct {
	Uid     uint32
	Unlocks uint16
	Version uint8
}

func (r *LoginResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x4c {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

func (r *LoginResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x4c}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

type LoginRequest struct {
	Secret  [8]byte
	NameLen uint8
	Name    [32]byte
}

func (r *LoginRequest) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x4c {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

func (r *LoginRequest) Prepare(user, password string) error {
	hash := sha256.Sum256([]byte(password))
	copy(r.Secret[:], hash[:8])

	if len(user) > 32 {
		return fmt.Errorf("user name length %d is longer than max (32)", len(user))
	}
	r.NameLen = uint8(len(user))
	copy(r.Name[:r.NameLen], user)

	return nil
}

func (r *LoginRequest) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x4c}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

type AlreadyLoggedInResponse struct{}

func (r *AlreadyLoggedInResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x59 {
		return false, nil
	}
	return true, nil
}

func (r *AlreadyLoggedInResponse) Serialize(w io.Writer) error {
	_, err := w.Write([]byte{0x59})
	return err
}

type ForceLogoutResponse struct{}

func (r *ForceLogoutResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x58 {
		return false, nil
	}
	return true, nil
}

func (r *ForceLogoutResponse) Serialize(w io.Writer) error {
	_, err := w.Write([]byte{0x58})
	return err
}

type EmojiRequest struct {
	Secret [8]byte
	Emoji  uint8
}

func (r *EmojiRequest) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x45}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *EmojiRequest) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x45 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type EmojiResponse struct {
	Uid   uint32
	Time  uint32
	Emoji uint8
}

func (r *EmojiResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x45}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *EmojiResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x45 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type TextResponse struct {
	Text string
}

func (r *TextResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x20}); err != nil {
		return err
	}
	_, err := w.Write([]byte(r.Text))
	return err
}

func (r *TextResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x20 {
		return false, nil
	}

	r.Text = string(payload[1:])
	return true, nil
}

type FlagResponse struct {
	Text string
}

func (r *FlagResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x43}); err != nil {
		return err
	}
	_, err := w.Write([]byte(r.Text))
	return err
}

func (r *FlagResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x43 {
		return false, nil
	}

	r.Text = string(payload[:])
	return true, nil
}

type HeartbeatRequest struct {
	Secret [8]byte
	Time   uint64
}

func (r *HeartbeatRequest) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x3c, 0x33}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *HeartbeatRequest) Parse(payload []byte) (bool, error) {
	if len(payload) < 11 || payload[0] != 0x3c || payload[1] != 0x33 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type HeartbeatResponse struct {
	Subtype         uint8
	Time            uint64
	StartServerTime uint64
}

func (r *HeartbeatResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x3c}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *HeartbeatResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x3c {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type InfoRequest struct {
	Secret [8]byte
	Uid    uint32
}

func (r *InfoRequest) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x49}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *InfoRequest) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x49 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type InfoResponse struct {
	Uid     uint32
	Unlocks uint16
	NameLen uint8
	Name    string
}

func (r *InfoResponse) Serialize(w io.Writer) error {
	_, err := w.Write([]byte{0x49})
	if err != nil {
		return err
	}
	err = binary.Write(w, binary.LittleEndian, r.Uid)
	if err != nil {
		return err
	}

	err = binary.Write(w, binary.LittleEndian, r.Unlocks)
	if err != nil {
		return err
	}

	if _, err := w.Write([]byte(r.Name)); err != nil {
		return err
	}

	return nil
}

func (r *InfoResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x49 {
		return false, nil
	}

	r.Uid = binary.LittleEndian.Uint32(payload[1:5])
	r.Unlocks = binary.LittleEndian.Uint16(payload[5:7])
	r.NameLen = uint8(payload[7])
	r.Name = string(payload[7:])

	return true, nil
}

type PlayerState struct {
	Time        uint64
	Pos         [3]int32
	Angle       [3]int32
	Trigger     byte
	Grounded    int16
	NotGrounded int16
}

type Player struct {
	Uid   uint32
	State PlayerState
}

type StateResponse struct {
	Players []Player
}

func (r *StateResponse) Serialize(w io.Writer) error {
	for _, p := range r.Players {
		_, err := w.Write([]byte{0x50})
		if err != nil {
			return err
		}

		err = binary.Write(w, binary.LittleEndian, p)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *StateResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x50 {
		return false, nil
	}

	for reader := bytes.NewReader(payload); reader.Len() >= 42; {
		magic, err := reader.ReadByte()
		if err != nil {
			return true, err
		}
		if magic != 0x50 {
			return true, fmt.Errorf("expected packet part to start with 0x50, instead got: %x", magic)
		}

		var player Player
		err = binary.Read(reader, binary.LittleEndian, &player)
		if err != nil {
			return true, err
		}

		r.Players = append(r.Players, player)
	}

	return true, nil
}

type StateRequest struct {
	Secret  [8]byte
	MyState PlayerState
}

func (r *StateRequest) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x50}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *StateRequest) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x50 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type TeleportResponse struct {
	Instant uint8
	Pos     [3]int32
}

func (r *TeleportResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x54}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *TeleportResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x54 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}

type CheckpointResponse struct {
	Idx uint8
}

func (r *CheckpointResponse) Serialize(w io.Writer) error {
	if _, err := w.Write([]byte{0x52}); err != nil {
		return err
	}
	return binary.Write(w, binary.LittleEndian, r)
}

func (r *CheckpointResponse) Parse(payload []byte) (bool, error) {
	if payload[0] != 0x52 {
		return false, nil
	}

	return true, binary.Read(bytes.NewReader(payload[1:]), binary.LittleEndian, r)
}


func (client *MazeConnection) RegisterTextHandlers() {
	client.AddHandler(func(payload []byte) bool {
		var flag FlagResponse
		if matched, err := flag.Parse(payload); matched {
			log.Printf("got flag: %s", flag.Text)
			if err != nil {
				log.Printf("flag parse error: %v", err)
			}
		}

		var text TextResponse
		if matched, err := text.Parse(payload); matched {
			log.Printf("message: %s", text.Text)
			if err != nil {
				log.Printf("text parse error: %v", err)
			}
		}

		return false
	})
}

func (client *MazeConnection) RegisterStateLogger() {
	client.AddHandler(func(payload []byte) bool {
		var state StateResponse
		if matched, err := state.Parse(payload); matched {
			if err != nil {
				log.Printf("state parse error: %v", err)
				return false
			}

			for _, player := range state.Players {
				log.Printf("[UID 0x%x] @%d %v", player.Uid, player.State.Time, player.State.Pos)
			}
		}
		return false
	})
}

func (client *MazeConnection) RegisterTeleportLogger() {
	client.AddHandler(func(payload []byte) bool {
		var teleport TeleportResponse
		if matched, err := teleport.Parse(payload); matched {
			if err != nil {
				log.Printf("teleport parse error: %v", err)
				return false
			}

			log.Printf("[TELEPORT] dest %d %d %d instant %d", teleport.Pos[0], teleport.Pos[1], teleport.Pos[2], teleport.Instant)
		}
		return false
	})
}

func (client *MazeConnection) RegisterHeartbeatLogger() {
	client.AddHandler(func(payload []byte) bool {
		var m HeartbeatResponse
		if matched, err := m.Parse(payload); matched {
			if err != nil {
				log.Printf("heartbeat parse error: %v", err)
			}
			log.Printf("[HEARTBEAT] client %08d server %08d", m.Time, m.StartServerTime)
		}
		return false
	})
}

func (client *MazeConnection) RegisterCheckpointLogger() {
	client.AddHandler(func(payload []byte) bool {
		var m CheckpointResponse
		if matched, err := m.Parse(payload); matched {
			if err != nil {
				log.Printf("checkpoint parse error: %v", err)
			}
			log.Printf("[CHECKPOINT] %d", m.Idx)
		}
		return false
	})
}

func (client *MazeConnection) RegisterForceLogoutLogger() {
	client.AddHandler(func(payload []byte) bool {
		var m ForceLogoutResponse
		if matched, err := m.Parse(payload); matched {
			if err != nil {
				log.Printf("heartbeat parse error: %v", err)
			}
			log.Printf("[LOGOUT] server forced logout")
		}
		return false
	})
}

func (client *MazeConnection) PrintFlag() error {
	var flag FlagResponse
	err := <-client.WaitForMessage(&flag)
	log.Printf("flag: %s", flag.Text)
	return err
}

func MessageBytes(msg NetMessage) []byte {
	var buffer bytes.Buffer
	msg.Serialize(&buffer)
	return buffer.Bytes()
}

func EncodeMessage(msg NetMessage) []byte {
	var buffer bytes.Buffer
	buffer.Write([]byte{0,0})
	msg.Serialize(&buffer)
	out := buffer.Bytes()
	EncodeCipher(out[:], out[2:])
	return out
}
