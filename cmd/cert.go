package cmd

import (
	"fmt"
	"mobproxy/core"
)

func GenerateCert() {
	err := core.GenerateCA()
	if err != nil {
		fmt.Println("Failed generate CA:", err)
		return
	}
	fmt.Println("[+] CA generated: ca.pem & ca.key")
	fmt.Println("[!] Install ca.pem to Android system cert store")
}
