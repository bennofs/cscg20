package maze

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"time"
)

const (
	DefaultRemote = "147.75.85.99:1339"
)

type Session struct {
	Conn   *MazeConnection
	Secret [8]byte
	Login  LoginResponse
}

func (s *Session) Close() error {
	return s.Conn.Close()
}

func (client *MazeConnection) Login(user, password string, requireNew bool) (*Session, error) {
	var resp LoginResponse
	errc := client.WaitForMessage(&resp)

	var req LoginRequest
	req.Prepare(user, password)

	done := make(chan struct{})
	defer close(done)

	client.AddHandler(func(payload []byte) bool {
		select {
		case _, ok := <-done:
			if !ok {
				return true
			}
		default:
			break
		}

		// retry after delay if already logged in
		var r AlreadyLoggedInResponse
		if matched, _ := r.Parse(payload); matched {
			if !requireNew {
				log.Printf("already logged in... faking response")

				resp.Uid = 0xdeadbeef
				resp.Unlocks = 0xffff
				resp.Version = 0x2
				errc <- nil
				close(errc)
				return true
			} else {
				log.Printf("already logged in. retrying in 3 seconds")
				time.Sleep(3 * time.Second)
				err := client.SendMessage(&req)
				if err != nil {
					errc <- err
				}
			}
		}

		return false
	})

	err := client.SendMessage(&req)
	if err != nil {
		return nil, err
	}

	err = <-errc
	return &Session{
		Conn:   client,
		Secret: req.Secret,
		Login:  resp,
	}, err
}

func CreateSession(requireNew bool) (*Session, TeleportResponse, error) {
	remote := flag.String("remote", DefaultRemote, "server to connect to")
	username := flag.String("user", "bennofs", "username to authenticate as")
	password := flag.String("pass", "jae8aH5u", "password for login")
	flag.Parse()

	var teleport TeleportResponse
	client, err := Connect(*remote)
	if err != nil {
		return nil, teleport, fmt.Errorf("connect: %v", err)
	}
	var teleportc chan error
	if requireNew {
		teleportc = client.WaitForMessage(&teleport)
	}

	client.RegisterForceLogoutLogger()

	s, err := client.Login(*username, *password, requireNew)
	if err != nil {
		return s, teleport, fmt.Errorf("login: %v", err)
	}

	if requireNew {
		err = <-teleportc
		if err != nil {
			return s, teleport, fmt.Errorf("waiting for initial teleport: %v", err)
		}
	}

	log.Printf("version %d uid %x (%x) secret %s pos %08d %08d",
		s.Login.Version,
		s.Login.Uid,
		s.Login.Unlocks,
		hex.EncodeToString(s.Secret[:]),
		teleport.Pos[0],
		teleport.Pos[2],
	)

	return s, teleport, err
}

func (s *Session) RequestInfo(uid uint32) (r InfoResponse, err error) {
	errc := s.Conn.WaitForMessage(&r)

	err = s.Conn.SendMessage(&InfoRequest{Secret: s.Secret, Uid: uid})

	err = <-errc
	return
}

func (s *Session) SendEmoji(emoji uint8) error {
	return s.Conn.SendMessage(&EmojiRequest{Secret: s.Secret, Emoji: emoji})
}

func (s *Session) SendHeartbeat(time uint64) error {
	return s.Conn.SendMessage(&HeartbeatRequest{Secret: s.Secret, Time: time})
}

func (s *Session) SendState(state PlayerState) error {
	return s.Conn.SendMessage(&StateRequest{Secret: s.Secret, MyState: state})
}

func (s *Session) StartPacemaker(interval time.Duration, start uint64, factor uint64) chan struct{} {
	if interval.Milliseconds() < 0 {
		panic("heartbeat interval must be positive")
	}

	done := make(chan struct{}, 1)
	go func() {
		t := start
		for {
			select {
			case _, ok := <-done:
				if !ok {
					log.Printf("pacemaker stopped")
					return
				}
			default:
			}
			s.SendHeartbeat(t * factor)
			time.Sleep(interval)
			t += uint64(interval.Milliseconds())
		}
	}()
	return done
}

func (s *Session) GetPosition() (MapPos, error) {
	packets, done := s.Conn.PacketChannel()
	defer close(done)

	var lastState time.Time
	for p := range(packets) {
		var teleport TeleportResponse
		if matched, err := teleport.Parse(p); matched {
			if err != nil {
				return MapPos{}, fmt.Errorf("teleport parse error: %v", err)
			}

			return MapPosFromGame(teleport.Pos), nil
		}

		var beat HeartbeatResponse
		if matched, err := beat.Parse(p); matched {
			if err != nil {
				return MapPos{}, fmt.Errorf("heartbeat parse error: %v", err)
			}

			now := time.Now()
			if (now.Sub(lastState) > 3 * time.Second) {
				lastState = now
				err = s.SendState(PlayerState{
					Pos:  [...]int32{-0x8ffffff, -0x8ffffff, -0x8ffffff},
					Time: beat.Time + 1,
				})
				if err != nil {
					return MapPos{}, fmt.Errorf("send state: %v", err)
				}
			}
		}
	}

	return MapPos{}, fmt.Errorf("packet channel closed")
}
