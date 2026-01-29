package cmd

import (
	"fmt"
	"mobproxy/core"
)

func StartProxy() {
	fmt.Println("[+] Starting FULL MITM proxy at :8080")
	core.StartMITM(":8080")
}
