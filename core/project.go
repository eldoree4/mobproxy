package core

import (
	"encoding/json"
	"os"
)

type Project struct {
	Scope    Scope      `json:"scope"`
	Findings []Finding  `json:"findings"`
}

func SaveProject(dir string) error {
	os.MkdirAll(dir, 0755)

	p := Project{
		Scope:    CurrentScope,
		Findings: Findings,
	}

	b, _ := json.MarshalIndent(p, "", "  ")
	return os.WriteFile(dir+"/project.json", b, 0644)
}

func LoadProject(dir string) error {
	b, err := os.ReadFile(dir + "/project.json")
	if err != nil {
		return err
	}

	var p Project
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}

	CurrentScope = p.Scope
	Findings = p.Findings
	return nil
}
