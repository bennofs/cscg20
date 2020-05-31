package maze

import (
	"log"
	"net"
	"time"
)

type ClientState struct {
	lastPacket time.Time
	Addr *net.UDPAddr
	packets chan []byte
	Packets <-chan []byte
	quit chan struct{}
}

func ListenForTakeover(listenAddr string) (net.PacketConn, chan *ClientState, error) {
	addrResolved, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.ListenUDP("udp", addrResolved)
	if err != nil {
		return nil, nil, err
	}

	clients := make(map[string]*ClientState)
	newClient := make(chan *ClientState, 1)
	buf := make([]byte, 512)
	go func() {
		defer close(newClient)
		for {
			n, caddr, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("ListenForTakeover read error: %v", err)
				return
			}

			// expire old clients
			now := time.Now()
			for addr, client := range clients {
				if now.Sub(client.lastPacket) > 10*time.Second {
					log.Printf("age %v\n", now.Sub(client.lastPacket))
					close(client.packets)
					close(client.quit)
					delete(clients, addr)
				}
			}

			// handle new client
			client, ok := clients[caddr.String()]
			if !ok  {
				log.Printf("new takeover client: %v", caddr)
				client = new(ClientState)
				client.Addr = caddr
				client.packets = make(chan []byte, 20)
				client.Packets = client.packets
				client.quit = make(chan struct{}, 1)

				newClient <- client
				clients[caddr.String()] = client
			}
			client.lastPacket = time.Now()

			// handle the message
			decoded := make([]byte, n-2)
			decoded = DecodeCipher(decoded, buf[:n])
			var response []byte

			client.packets <- decoded

			var login LoginRequest
			if matched, err := login.Parse(decoded); matched {
				if err != nil {
					log.Printf("login request parse error: %v", err)
					continue
				}

				response = EncodeMessage(&LoginResponse {
					Uid: 0xbeef,
					Unlocks: 0x0,
					Version: 2,
				})
			}

			var beat HeartbeatRequest
			if matched, err := beat.Parse(decoded); matched {
				if err != nil {
					log.Printf("heartbeat request parse error: %v", err)
					continue
				}

				response = EncodeMessage(&HeartbeatResponse {
					Subtype: 0x33,
					Time: beat.Time,
					StartServerTime: uint64(time.Now().Unix()),
				})
			}

			if response != nil {
				_, err = conn.WriteTo(response, caddr)
				if err != nil {
				log.Printf("takeover client %v: write error: %v", caddr, err)
					close(client.packets)
				close(client.quit)
				delete(clients, caddr.String())
				}
			}
	}

	}()

	return conn, newClient, nil
}
