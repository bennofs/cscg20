package maze

import (
	"io"
	"log"
	"net"
	"time"
)

type UdpClient struct {
	conn     net.PacketConn
	peerRead io.ReadCloser
	peer     net.Addr
}

func (u *UdpClient) Close() error {
	return u.peerRead.Close()
	// don't close the packet connection, it's shared
}

func (u *UdpClient) Write(buf []byte) (int, error) {
	return u.conn.WriteTo(buf, u.peer)
}

func (u *UdpClient) Read(buf []byte) (int, error) {
	return u.peerRead.Read(buf)
}

type MazeClient struct {
	udp        *UdpClient
	input      io.WriteCloser
	maze       *MazeConnection
	lastPacket time.Time

	stop chan struct{}
}

func (m *MazeClient) Close() error {
	m.maze.Close()
	m.input.Close()
	close(m.stop)
	return nil
}

func NewMazeClient(conn net.PacketConn, loginRes LoginResponse, addr net.Addr, packets chan []byte) (MazeClient, error) {
	peerRead, peerWrite := io.Pipe()
	udp := &UdpClient{
		conn:     conn,
		peerRead: peerRead,
		peer:     addr,
	}
	maze := WrapMaze(udp)

	// handle login
	maze.AddHandler(func(payload []byte) bool {
		var req LoginRequest
		if matched, err := req.Parse(payload); matched {
			log.Printf("login from %v", addr)
			if err != nil {
				log.Printf("login parser error: %v", err)
			}

			maze.SendMessage(&loginRes)
			return true
		}

		return false
	})

	// push packets
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case data := <-packets:
				_, err := maze.Write(data)
				if err != nil {
					log.Printf("maze client write error: %v", err)
				}
			case _, ok := <-stop:
				if !ok {
					return
				}
			}
		}
	}()

	return MazeClient{
		udp:        udp,
		input:      peerWrite,
		maze:       maze,
		lastPacket: time.Now(),
		stop:       stop,
	}, nil
}

func SpawnServer(listenAddr string, loginRes LoginResponse, packets chan []byte) error {
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return err
	}

	clients := make(map[string]*MazeClient)
	defer func() {
		for _, client := range clients {
			client.Close()
		}
	}()

	go func() {
		buffer := make([]byte, 512)
		for {
			// expire old clients
			now := time.Now()
			for addr, client := range clients {
				if now.Sub(client.lastPacket) > 10*time.Second {
					log.Printf("age %v\n", now.Sub(client.lastPacket))
					client.Close()
					delete(clients, addr)
				}
			}

			// handle packets (read from clients)
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				log.Printf("output server read error: %v", err)
				return
			}

			client, ok := clients[addr.String()]
			if !ok {
				log.Printf("new client: %v", addr)
				newClient, err := NewMazeClient(conn, loginRes, addr, packets)
				if err != nil {
					log.Printf("create maze client error: %v", err)
					return
				}
				client = &newClient
				clients[addr.String()] = client
			}
			client.lastPacket = now
			_, err = client.input.Write(buffer[:n])
			if err != nil {
				log.Printf("maze client write error: %v", err)
				return
			}
		}

	}()

	return nil
}
