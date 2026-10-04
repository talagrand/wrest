// A minimal TLS server that asks for a client cert
//
// /client-cert answers "none" when the client presented no certificate and
// "present" when it did.  It is served on two ports: -optional-addr
// requests a client certificate but does not require one, -require-addr
// requires it.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	optionalAddr := flag.String("optional-addr", "127.0.0.1:18443", "listen address, client certificate optional")
	requireAddr := flag.String("require-addr", "127.0.0.1:18444", "listen address, client certificate required")
	flag.Parse()

	cert, err := selfSignedServerCert()
	if err != nil {
		log.Fatalf("generating server certificate: %v", err)
	}

	optionalListener, optionalServer, err := bind(*optionalAddr, cert, tls.RequestClientCert)
	if err != nil {
		log.Fatalf("listening on %s: %v", *optionalAddr, err)
	}
	requiredListener, requiredServer, err := bind(*requireAddr, cert, tls.RequireAnyClientCert)
	if err != nil {
		log.Fatalf("listening on %s: %v", *requireAddr, err)
	}

	// Both ports are bound before the readiness line the CI action waits for.
	fmt.Printf("mtls-server ready on %s (optional) and %s (required)\n",
		optionalListener.Addr(), requiredListener.Addr())

	go func() {
		log.Fatal(requiredServer.ServeTLS(requiredListener, "", ""))
	}()
	log.Fatal(optionalServer.ServeTLS(optionalListener, "", ""))
}

// bind opens a listener and builds a server that serves /client-cert with the
// given client-authentication mode.
func bind(addr string, cert tls.Certificate, auth tls.ClientAuthType) (net.Listener, *http.Server, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	server := &http.Server{
		Handler: http.HandlerFunc(clientCertHandler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientAuth:   auth,
			MinVersion:   tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	return listener, server, nil
}

// clientCertHandler reports whether the client presented a certificate.
func clientCertHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		fmt.Fprint(w, "none")
		return
	}
	fmt.Fprint(w, "present")
}

// selfSignedServerCert builds a throwaway certificate for 127.0.0.1.  The
// tests disable certificate validation, so it only has to be well-formed.
func selfSignedServerCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "wrest-test-server"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}, nil
}
