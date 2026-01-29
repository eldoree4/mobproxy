package core

import (
	"encoding/json"
	"os"
	"strings"
)

type Scope struct {
	Include []string `json:"include"`
	Exclude []string `json:"exclude"`
}

var CurrentScope = Scope{
	Include: []string{},
	Exclude: []string{},
}

func InScope(url string) bool {
	for _, ex := range CurrentScope.Exclude {
		if strings.Contains(url, ex) {
			return false
		}
	}
	if len(CurrentScope.Include) == 0 {
		return true
	}
	for _, in := range CurrentScope.Include {
		if strings.Contains(url, in) {
			return true
		}
	}
	return false
}

func SaveScope(file string) error {
	b, _ := json.MarshalIndent(CurrentScope, "", "  ")
	return os.WriteFile(file, b, 0644)
}

func LoadScope(file string) error {
	b, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &CurrentScope)
}

