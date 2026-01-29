package cmd

import (
	"fmt"
	"os"
)

func ShowHistory() {
	data, _ := os.ReadFile("history.log")
	fmt.Println(string(data))
}
