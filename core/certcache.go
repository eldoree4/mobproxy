package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

var certCache = map[string]*tls.Certificate{}
var certLock sync.Mutex

func GetCertForHost(host string) *tls.Certificate {
	certLock.Lock()
	defer certLock.Unlock()

	if c, ok := certCache[host]; ok {
		return c
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			CommonName: host,
		},
		DNSNames:  []string{host},
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(1, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
	}

	derBytes, _ := x509.CreateCertificate(rand.Reader, &template, CACert, &priv.PublicKey, CAKey)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{derBytes, CACert.Raw},
		PrivateKey:  priv,
	}

	certCache[host] = &tlsCert
	return &tlsCert
}
