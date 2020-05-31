package main

import (
	"os/exec"
	"fmt"
	"strings"
	"time"
)

const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

func main() {
	prefix := "n3w_ag3_v1rtu4liz4t1on_";
	for _, b1 := range(alphabet) {
		for _, b2 := range(alphabet) {
			start := time.Now()
			for i, b3 := range(alphabet) {
				for _, b4 := range(alphabet) {
					cmd := exec.Command("./eVMoji", "code.bin");
					flag := prefix + string([]rune{b1,b2,b3,b4});
					cmd.Stdin = strings.NewReader(flag);
					out, _ := cmd.Output()
					if !strings.HasSuffix(string(out), "Gotta go cyclic ♻️\n") {
						fmt.Println(flag)
						fmt.Print(string(out))
						return
					}
				}
				if i % 10 == 9 {
					duration := time.Since(start)
					fmt.Printf("b3: %d exec per sec: %v\n", i, float64(i * len(alphabet)) / duration.Seconds())
				}
			}
		}
	}
}
