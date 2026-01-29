package core

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

var payloadFile string
var intruderMode = "sniper"

func IntruderSetPayloadFile(f string) {
	payloadFile = f
}

func IntruderSetMode(m string) {
	intruderMode = m
}

func StartIntruder(req *RawRequest) {
	if payloadFile == "" {
		fmt.Println("payload file not set")
		return
	}

	f, _ := os.Open(payloadFile)
	defer f.Close()

	sc := bufio.NewScanner(f)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 10) // 10 threads

	for sc.Scan() {
		payload := sc.Text()

		wg.Add(1)
		sem <- struct{}{}

		go func(p string) {
			defer wg.Done()
			defer func() { <-sem }()

			raw := req.WithPayload(p)
			resp, err := SendRaw(raw)
			if err != nil {
				return
			}

			if strings.Contains(resp, "SQL") || strings.Contains(resp, "error") {
				fmt.Println("[!!!] Possible hit with payload:", p)
			} else {
				fmt.Println("[*] tried:", p)
			}
		}(payload)
	}

	wg.Wait()
	fmt.Println("[+] Intruder finished")
}
