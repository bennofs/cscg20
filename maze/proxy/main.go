package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"log"

	"five.name/cscg/maze"
)

const (
	maxBufferSize = 1024
)

func DecodeCipher(out, data []byte) []byte {
	curkey := data[0]
	key := data[1]

	for idx := 0; idx+2 < len(data); idx += 1 {
		out[idx] = data[idx+2] ^ curkey
		curkey = curkey + key + byte((uint16(key)+uint16(curkey))/0x100)
	}

	return out
}

func EncodeCipher(out, data []byte) []byte {
	curkey := out[0]
	key := out[1]

	for idx := 0; idx+2 < len(data); idx += 1 {
		out[idx+2] = data[idx] ^ curkey
		curkey = curkey + key + byte((uint16(key)+uint16(curkey))/0x100)
	}

	return out
}

var prevOpcode = byte(0)
var prevTag = ""

func PrintPacket(tag string, data []byte) {
	if data[0] == prevOpcode && tag == prevTag {
		fmt.Printf("\r[%d %d] %s %s", len(data), data[0], tag, hex.EncodeToString(data))
	} else {
		prevOpcode = data[0]
		fmt.Printf("\n[%d %d] %s %s", len(data), data[0], tag, hex.EncodeToString(data))
	}
}

func SendPacket(sock net.PacketConn, client net.Addr, data string) {
	buf, err := hex.DecodeString(data)
	if err != nil {
		fmt.Printf("err %v\n", err)
	}
	out := make([]byte, len(buf)+2)
	EncodeCipher(out, buf)
	sock.WriteTo(out, client)
}

/*
 * serve as the UPD Server with context support
 */
func serve(address string) (err error) {
	fmt.Printf("UDP Server listening on: \"%s\"\n", address)

	local, err := net.ListenPacket("udp", address)
	if err != nil {
		return
	}
	defer local.Close()

	remote, err := net.Dial("udp", "147.75.85.99:1337")
	if err != nil {
		return
	}
	defer remote.Close()

	doneChan := make(chan error, 1)
	var client net.Addr
	emoji := byte(0)

	injectChan := make(chan []byte)
	udpListener, _ := net.ListenPacket("udp", ":2345")
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, _ := udpListener.ReadFrom(buffer)
			injectChan <- buffer[:n]
		}
	}()

	injectRemoteChan := make(chan []byte)
	remoteUdpListener, _ := net.ListenPacket("udp", ":2346")
	go func() {
		buffer := make([]byte, 1024)
		for {
			n, _, _ := remoteUdpListener.ReadFrom(buffer)
			injectRemoteChan <- buffer[:n]
		}
	}()

	go func() {
		buffer := make([]byte, maxBufferSize)
		decoded := make([]byte, maxBufferSize)
		for {
			n, addr, err := local.ReadFrom(buffer)
			client = addr
			if err != nil {
				doneChan <- err
				return
			}

			DecodeCipher(decoded, buffer[:n])

			var emojiReq maze.EmojiRequest
			if matched, _ := emojiReq.Parse(decoded); matched {
				emoji = emojiReq.Emoji
				log.Printf("emoji: %v", emoji)
			}

			out := buffer[:n]
			var stateReq maze.StateRequest
			if matched, _ := stateReq.Parse(decoded); matched {
				if emoji == 0x17 || emoji == 0x16 {
					log.Printf("UPDATE POS\n")
					newPos := stateReq.MyState.Pos
					if emoji == 0x16 {
						newPos[1] += 20000
					} else {
						newPos[1] -= 5000
					}
					if newPos[1] < 0 {
						newPos[1] = 0
					}
					local.WriteTo(maze.EncodeMessage(&maze.TeleportResponse{
						Pos:     newPos,
						Instant: 1,
					}), client)
				}
			}

			select {
			case toinject := <-injectRemoteChan:
				fmt.Printf("REMOTE INJECT! %s\n", hex.EncodeToString(toinject))
				remote.Write(toinject)
			default:
			}

			idx := 0
			for idx < n {
				written, err := remote.Write(out[idx:])
				if err != nil {
					return
				}
				idx += written
			}
		}
	}()

	go func() {
		buffer2 := make([]byte, maxBufferSize)
		decoded2 := make([]byte, maxBufferSize)
		for {
			n, err := remote.Read(buffer2)
			if err != nil {
				doneChan <- err
				return
			}

			DecodeCipher(decoded2, buffer2[:n])
			if decoded2[0] == 0x52 {
				log.Printf("recv raze: %s", hex.EncodeToString(decoded2[:n-2]))
			}

			select {
			case toinject := <-injectChan:
				fmt.Printf("LOCAL INJECT! %s\n", hex.EncodeToString(toinject))
				local.WriteTo(toinject, client)
			default:
			}

			var teleport maze.TeleportResponse
			if matched, _ := teleport.Parse(decoded2); matched {
				if emoji == 4 {
					log.Printf("ignoring teleport")
					continue
				}
			}


			idx := 0
			for idx < n {
				written, err := local.WriteTo(buffer2[idx:n], client)
				if err != nil {
					doneChan <- err
					return
				}
				idx += written
			}
		}
	}()

	select {
	case err = <-doneChan:
	}

	return
}

func main() {
	err := serve("localhost:1337")
	if err != nil {
		fmt.Printf("error: %v\n", err)
	}
}
