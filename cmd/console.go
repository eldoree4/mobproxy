package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"mobproxy/core"
)

var currentReq *core.RawRequest

func StartConsole() {
	fmt.Println("mobproxy interactive console")
	sc := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("mobproxy> ")
		if !sc.Scan() {
			break
		}
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}

		args := strings.Split(line, " ")

		switch args[0] {
		case "exit", "quit":
			return

		case "history":
			core.ShowHistoryShort()

		case "use":
			if len(args) < 2 {
				fmt.Println("use <id>")
				continue
			}
			r, err := core.LoadRequestByID(args[1])
			if err != nil {
				fmt.Println("error:", err)
				continue
			}
			currentReq = r
			fmt.Println("[+] Request loaded")

		case "show":
			if currentReq == nil {
				fmt.Println("no request selected")
				continue
			}
			fmt.Println(currentReq.Raw)

		case "intruder":
			handleIntruder(args[1:])

		default:
			fmt.Println("commands: history, use, show, intruder, exit")
		}
	}
}

func handleIntruder(args []string) {
	if len(args) == 0 {
		fmt.Println("intruder set payloads <file> | set mode <sniper> | start")
		return
	}

	switch args[0] {
	case "set":
		if args[1] == "payloads" {
			core.IntruderSetPayloadFile(args[2])
			fmt.Println("[+] payload file set")
		} else if args[1] == "mode" {
			core.IntruderSetMode(args[2])
			fmt.Println("[+] mode set")
		}
	case "start":
		if currentReq == nil {
			fmt.Println("no request selected")
			return
		}
		core.StartIntruder(currentReq)
	}
}
