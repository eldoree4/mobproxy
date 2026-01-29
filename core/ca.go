package core

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
)

var CACert *x509.Certificate
var CAKey interface{}

func LoadCA() {
	certPEM, _ := os.ReadFile("ca.pem")
	keyPEM, _ := os.ReadFile("ca.key")

	block, _ := pem.Decode(certPEM)
	CACert, _ = x509.ParseCertificate(block.Bytes)

	keyBlock, _ := pem.Decode(keyPEM)
	CAKey, _ = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
}

func LoadCAForTLS() tls.Certificate {
	cert, _ := tls.X509KeyPair(
		must(os.ReadFile("ca.pem")),
		must(os.ReadFile("ca.key")),
	)
	return cert
}

func must[T any](v T, _ error) T { return v }
