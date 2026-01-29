package core

import (
	"bufio"
	"crypto/tls"
	"net"
	"strings"
)

func SendRaw(raw string) (string, error) {
	lines := strings.Split(raw, "\n")
	host := ""
	for _, l := range lines {
		if strings.HasPrefix(strings.ToLower(l), "host:") {
			host = strings.TrimSpace(strings.SplitN(l, ":", 2)[1])
		}
	}

	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.Write([]byte(raw))

	br := bufio.NewReader(conn)
	resp, _ := br.ReadString('\n')
	return resp, nil
}
