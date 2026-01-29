package core

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
)

func StartMITM(addr string) {
	LoadCA()
	server := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(handleHTTP),
	}
	server.ListenAndServe()
}

func handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "CONNECT" {
		handleHTTPS(w, r)
		return
	}
	handlePlainHTTP(w, r)
}

func handlePlainHTTP(w http.ResponseWriter, r *http.Request) {
	SaveLog([]byte(r.Method + " " + r.URL.String()))
	resp, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	copyResponse(w, resp)
}

func handleHTTPS(w http.ResponseWriter, r *http.Request) {
	hij, _ := w.(http.Hijacker)
	clientConn, _, _ := hij.Hijack()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	host := strings.Split(r.Host, ":")[0]

	tlsToClient := tls.Server(clientConn, &tls.Config{
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return GetCertForHost(host), nil
		},
	})
	tlsToClient.Handshake()

	serverConn, _ := tls.Dial("tcp", r.Host, &tls.Config{
		InsecureSkipVerify: true,
	})

	go transfer(serverConn, tlsToClient)
	go transfer(tlsToClient, serverConn)
}

func transfer(dst net.Conn, src net.Conn) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func copyResponse(w http.ResponseWriter, resp *http.Response) {
	for k, v := range resp.Header {
		for _, vv := range v {
			w.Header().Add(k, vv)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}
