package core

import (
	"fmt"
	"os"
)

var counter = 0

func SaveRequest(raw string) {
	counter++
	os.MkdirAll("history", 0755)
	fn := fmt.Sprintf("history/%d.txt", counter)
	os.WriteFile(fn, []byte(raw), 0644)
}

func ShowHistoryShort() {
	files, _ := os.ReadDir("history")
	for _, f := range files {
		fmt.Println(f.Name())
	}
}

func LoadRequestByID(id string) (*RawRequest, error) {
	b, err := os.ReadFile("history/" + id + ".txt")
	if err != nil {
		return nil, err
	}
	return ParseRawRequest(string(b)), nil
}
