package cert

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"
)

const (
	CertFile = "cert.pem"
	KeyFile  = "key.pem"
)

// InitCertificates ensures valid certificates exist or generates new ones
func InitCertificates() (cert, key []byte, err error) {
	// Check if certificates already exist
	if cert, key, err = loadCertificates(); err == nil {
		return cert, key, nil
	}

	// Generate new certificates
	return generateCertificates()
}

func loadCertificates() ([]byte, []byte, error) {
	cert, err := os.ReadFile(CertFile)
	if err != nil {
		return nil, nil, err
	}

	key, err := os.ReadFile(KeyFile)
	if err != nil {
		return nil, nil, err
	}

	return cert, key, nil
}

func generateCertificates() ([]byte, []byte, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Get system hostname
	hostname, err := os.Hostname()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get hostname: %v", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"CyberDock"},
			CommonName:   hostname,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("0.0.0.0"),
		},
		DNSNames: []string{
			"localhost",
			hostname,
			"127.0.0.1",
			"0.0.0.0",
		},
	}

	// Create certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate
	certBuf := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: derBytes,
	})

	// Encode private key
	keyBuf := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Save to files
	if err := os.WriteFile(CertFile, certBuf, 0644); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(KeyFile, keyBuf, 0600); err != nil {
		return nil, nil, err
	}

	return certBuf, keyBuf, nil
}
