package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cyberdock/internal/cert"
	"github.com/cyberdock/internal/registry"
	"github.com/cyberdock/internal/ui"
)

const (
	defaultRegistryPort = 5000
	defaultUIPort       = 5001
	version             = "0.3.0d"
)

// These will be set at build time
var (
	telemetryToken string
	telemetryURL   string
)

type telemetryData struct {
	SystemID string `json:"system_id"`
	Version  string `json:"version"`
	Token    string `json:"token"`
}

func getSystemID() string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "cyberdock_unknown"
	}

	// Find the first non-loopback interface with a MAC address
	var macAddr string
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			macAddr = iface.HardwareAddr.String()
			break
		}
	}

	if macAddr == "" {
		return "cyberdock_unknown"
	}

	// Create a hash of the MAC address
	hasher := sha256.New()
	hasher.Write([]byte(macAddr))
	hash := hex.EncodeToString(hasher.Sum(nil))

	// Return first 12 characters of hash prefixed with cyberdock_
	return "cyberdock_" + hash[:12]
}

func checkTelemetry() {
	data := telemetryData{
		SystemID: getSystemID(),
		Version:  version,
		Token:    telemetryToken,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	req, err := http.NewRequest("POST", telemetryURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return
	}

	req.Header.Set("X-API-Token", telemetryToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	var result struct {
		Authorized int    `json:"authorized"`
		Timestamp  string `json:"timestamp"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return
	}

	if result.Authorized != 1 {
		return
	}
}

func main() {
	// Check telemetry first
	checkTelemetry()

	// Parse command line flags
	registryPort := flag.Int("r", defaultRegistryPort, "Port for Docker registry")
	uiPort := flag.Int("g", defaultUIPort, "Port for web UI")
	flag.Parse()

	// Initialize certificates
	certData, keyData, err := cert.InitCertificates()
	if err != nil {
		log.Fatalf("Failed to initialize certificates: %v", err)
	}

	// Create registry server
	registryServer, err := registry.NewServer(certData, keyData, *registryPort, "data")
	if err != nil {
		log.Fatalf("Failed to create registry server: %v", err)
	}

	// Create UI server with registry instance
	uiServer := ui.NewServer(certData, keyData, cert.CertFile, cert.KeyFile, *uiPort, registryServer, version)

	// Start registry server in a goroutine
	go func() {
		if err := registryServer.Start(); err != nil {
			log.Fatalf("Registry server failed: %v", err)
		}
	}()

	// Start UI server in a goroutine
	go func() {
		if err := uiServer.Start(); err != nil {
			log.Fatalf("UI server failed: %v", err)
		}
	}()

	// Start periodic telemetry checks
	go func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				checkTelemetry()
			}
		}
	}()

	// Wait for interrupt signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down servers...")
}
