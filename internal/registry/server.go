package registry

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyberdock/internal/storage"
	"github.com/gorilla/mux"
	"github.com/opencontainers/go-digest"
)

// ManifestV2 represents a Docker image manifest
type ManifestV2 struct {
	SchemaVersion int    `json:"schemaVersion"`
	MediaType     string `json:"mediaType"`
	Config        struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Size      int64  `json:"size"`
		Digest    string `json:"digest"`
	} `json:"layers"`
}

// OCIIndex represents an OCI image index
type OCIIndex struct {
	SchemaVersion int           `json:"schemaVersion"`
	MediaType     string        `json:"mediaType"`
	Manifests     []OCIManifest `json:"manifests"`
}

// OCIManifest represents an OCI image manifest
type OCIManifest struct {
	MediaType string    `json:"mediaType"`
	Size      int64     `json:"size"`
	Digest    string    `json:"digest"`
	Platform  *Platform `json:"platform,omitempty"`
}

// ImageInfo represents information about a Docker image
type ImageInfo struct {
	Repository string      `json:"repository"`
	Name       string      `json:"name"`
	Tag        string      `json:"tag"`
	MediaType  string      `json:"mediaType"`
	Digest     string      `json:"digest"`
	Size       int64       `json:"size"`
	Created    time.Time   `json:"created"`
	Layers     []LayerInfo `json:"layers"`
	Platform   *Platform   `json:"platform,omitempty"`
}

// Platform represents the platform information for an image
type Platform struct {
	Architecture string   `json:"architecture"`
	OS           string   `json:"os"`
	Variant      string   `json:"variant,omitempty"`
	OSVersion    string   `json:"osVersion,omitempty"`
	OSFeatures   []string `json:"osFeatures,omitempty"`
	Features     []string `json:"features,omitempty"`
}

// LayerInfo represents information about an image layer
type LayerInfo struct {
	MediaType string `json:"mediaType"`
	Digest    string `json:"digest"`
	Size      int64  `json:"size"`
}

// Server represents the Docker registry server
type Server struct {
	cert     []byte
	key      []byte
	port     int
	dataDir  string
	paths    *storage.PathManager
	router   *mux.Router
	manifest map[string][]string
	uploads  map[string]string // upload UUID -> temp file path
	mu       sync.RWMutex
}

// Manifest content types
const (
	manifestV2       = "application/vnd.docker.distribution.manifest.v2+json"
	manifestList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	manifestOCI      = "application/vnd.oci.image.manifest.v1+json"
	manifestOCIIndex = "application/vnd.oci.image.index.v1+json"
	configJSON       = "application/vnd.docker.container.image.v1+json"
	layerTar         = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// NewServer creates a new registry server instance
func NewServer(cert, key []byte, port int, dataDir string) (*Server, error) {
	s := &Server{
		cert:     cert,
		key:      key,
		port:     port,
		dataDir:  dataDir,
		paths:    storage.NewPathManager(dataDir),
		manifest: make(map[string][]string),
		uploads:  make(map[string]string),
	}

	// Initialize router
	s.router = mux.NewRouter()
	s.router.HandleFunc("/v2/", s.handleAPIVersion).Methods("GET")
	s.router.HandleFunc("/v2/_catalog", s.handleCatalog).Methods("GET")
	s.router.HandleFunc("/v2/{repository:.+}/tags/list", s.handleTagsList).Methods("GET")
	s.router.HandleFunc("/v2/{repository:.+}/manifests/{reference}", s.handleManifests).Methods("GET", "PUT", "DELETE")
	s.router.HandleFunc("/v2/{repository:.+}/blobs/uploads/", s.handleBlobUpload).Methods("POST")
	s.router.HandleFunc("/v2/{repository:.+}/blobs/uploads/{uuid}", s.handleBlobUpload).Methods("PATCH", "PUT")
	s.router.HandleFunc("/v2/{repository:.+}/blobs/{digest}", s.handleBlobs).Methods("GET", "HEAD", "DELETE")

	// Ensure required directories exist
	if err := s.paths.EnsureDirectories(""); err != nil {
		return nil, fmt.Errorf("failed to create directories: %v", err)
	}

	// Initialize the manifest and uploads maps
	s.manifest = make(map[string][]string)
	s.uploads = make(map[string]string)

	// Scan existing tags
	if err := s.scanExistingTags(); err != nil {
		log.Printf("WARNING: Failed to scan existing tags: %v", err)
	}

	return s, nil
}

// addCorsHeaders adds CORS headers to the response
func addCorsHeaders(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Accept, Range")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
}

// corsMiddleware handles CORS preflight requests
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addCorsHeaders(w)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r)
	}
}

// Start initializes and starts the registry server
func (s *Server) Start() error {
	// Ensure data directory exists
	if err := os.MkdirAll(s.dataDir, 0755); err != nil {
		return fmt.Errorf("failed to create data directory: %v", err)
	}

	// Ensure temp directory exists
	if err := os.MkdirAll(filepath.Join(s.dataDir, "temp"), 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %v", err)
	}

	// Configure TLS
	cert, err := tls.X509KeyPair(s.cert, s.key)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %v", err)
	}

	// Create TCP listener with explicit IPv4
	addr := &net.TCPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: s.port,
	}
	ln, err := net.ListenTCP("tcp4", addr)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	log.Printf("DEBUG: Created TCP4 listener on %s", ln.Addr().String())

	// Wrap with TLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.NoClientCert,
	}

	tlsListener := tls.NewListener(ln, tlsConfig)

	// Use Gorilla router with CORS middleware
	handler := corsMiddleware(s.router.ServeHTTP)

	server := &http.Server{
		Handler:  http.HandlerFunc(handler),
		ErrorLog: log.New(os.Stdout, "REGISTRY: ", log.LstdFlags),
	}

	log.Printf("Starting registry server on %s", ln.Addr().String())
	return server.Serve(tlsListener)
}

// handleV2API handles all v2 API requests
func (s *Server) handleV2API(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: Handling %s request to %s from %s", r.Method, r.URL.Path, r.RemoteAddr)
	log.Printf("DEBUG: Request headers: %v", r.Header)

	// Set common headers
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, HEAD, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Accept, Content-Type")

	path := strings.TrimPrefix(r.URL.Path, "/v2/")

	switch {
	case path == "":
		log.Printf("DEBUG: Handling base v2 API check")
		w.WriteHeader(http.StatusOK)
		return

	case path == "_catalog":
		log.Printf("DEBUG: Handling catalog request")
		s.handleCatalog(w, r)
		return

	case strings.Contains(path, "/tags/list"):
		log.Printf("DEBUG: Handling tags list request")
		s.handleTagsList(w, r)
		return

	case strings.Contains(path, "/blobs/uploads/"):
		log.Printf("DEBUG: Handling blob upload: %s", path)
		s.handleBlobUpload(w, r)
		return

	case strings.Contains(path, "/blobs/"):
		log.Printf("DEBUG: Handling blob request: %s", path)
		s.handleBlobs(w, r)
		return

	case strings.Contains(path, "/manifests/"):
		log.Printf("DEBUG: Handling manifest request: %s", path)
		s.handleManifests(w, r)
		return

	default:
		log.Printf("DEBUG: Handling repository request: %s", path)
		s.handleRepository(w, r)
	}
}

// handleBlobUpload handles blob upload operations
func (s *Server) handleBlobUpload(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	uuid := vars["uuid"]

	log.Printf("DEBUG: Handling blob upload for repository: '%s', uuid: '%s', method: %s", repository, uuid, r.Method)

	switch r.Method {
	case "POST":
		log.Printf("DEBUG: Starting new blob upload for repository: '%s'", repository)
		// Ensure repository directories exist
		if err := s.paths.EnsureDirectories(repository); err != nil {
			log.Printf("ERROR: Failed to ensure directories: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Generate new UUID for upload
		uuid = generateUUID()
		uploadPath := s.paths.GetUploadPath(uuid)

		// Create upload directory
		if err := os.MkdirAll(filepath.Dir(uploadPath), 0755); err != nil {
			log.Printf("ERROR: Failed to create upload directory: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Create empty upload file
		file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Printf("ERROR: Failed to create upload file: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		file.Close()

		// Store upload path in memory
		s.mu.Lock()
		s.uploads[uuid] = uploadPath
		s.mu.Unlock()

		// Set response headers
		location, err := s.paths.GetAPIPath(repository, fmt.Sprintf("blobs/uploads/%s", uuid))
		if err != nil {
			log.Printf("ERROR: Failed to get API path: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", location)
		w.Header().Set("Docker-Upload-UUID", uuid)
		w.Header().Set("Range", "0-0")
		w.WriteHeader(http.StatusAccepted)

	case "PUT":
		// Get upload path
		s.mu.RLock()
		uploadPath, exists := s.uploads[uuid]
		s.mu.RUnlock()

		if !exists {
			log.Printf("ERROR: Upload not found for UUID: %s", uuid)
			http.Error(w, "upload not found", http.StatusNotFound)
			return
		}

		// Get digest from query parameters
		digest := r.URL.Query().Get("digest")
		if digest == "" {
			log.Printf("ERROR: Missing digest parameter")
			http.Error(w, "digest parameter required", http.StatusBadRequest)
			return
		}

		// Verify digest if there's content in the PUT request
		if r.ContentLength > 0 {
			file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_APPEND, 0644)
			if err != nil {
				log.Printf("ERROR: Failed to open upload file: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if _, err := io.Copy(file, r.Body); err != nil {
				file.Close()
				log.Printf("ERROR: Failed to write final chunk: %v", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			file.Close()
		}

		// Verify the digest matches
		uploadedData, err := os.ReadFile(uploadPath)
		if err != nil {
			log.Printf("ERROR: Failed to read uploaded file for verification: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		actualDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(uploadedData))
		if actualDigest != digest {
			log.Printf("ERROR: Digest mismatch. Expected: %s, Got: %s", digest, actualDigest)
			http.Error(w, "digest mismatch", http.StatusBadRequest)
			return
		}

		// Move upload to final location
		blobPath, err := s.paths.GetBlobPath(repository, digest)
		if err != nil {
			log.Printf("ERROR: Failed to get blob path: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if err := os.MkdirAll(filepath.Dir(blobPath), 0755); err != nil {
			log.Printf("ERROR: Failed to create blob directory: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Move the file
		if err := os.Rename(uploadPath, blobPath); err != nil {
			log.Printf("ERROR: Failed to move blob to final location: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("DEBUG: Successfully stored blob %s for repository %s", digest, repository)

		// Remove upload from memory
		s.mu.Lock()
		delete(s.uploads, uuid)
		s.mu.Unlock()

		// Set response headers
		w.Header().Set("Docker-Content-Digest", digest)
		location, err := s.paths.GetAPIPath(repository, fmt.Sprintf("blobs/%s", digest))
		if err != nil {
			log.Printf("ERROR: Failed to get API path: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", location)
		w.WriteHeader(http.StatusCreated)

	case "PATCH":
		// Get upload path
		s.mu.RLock()
		uploadPath, exists := s.uploads[uuid]
		s.mu.RUnlock()

		if !exists {
			log.Printf("ERROR: Upload not found for UUID: %s", uuid)
			http.Error(w, "upload not found", http.StatusNotFound)
			return
		}

		// Get current file size for range header
		info, err := os.Stat(uploadPath)
		if err != nil {
			log.Printf("ERROR: Failed to stat upload file: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		startRange := info.Size()

		// Open upload file for appending
		file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("ERROR: Failed to open upload file: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		// Copy request body to file
		written, err := io.Copy(file, r.Body)
		if err != nil {
			log.Printf("ERROR: Failed to write to upload file: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		log.Printf("DEBUG: Wrote %d bytes to blob upload %s", written, uuid)

		// Set response headers
		location, err := s.paths.GetAPIPath(repository, fmt.Sprintf("blobs/uploads/%s", uuid))
		if err != nil {
			log.Printf("ERROR: Failed to get API path: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Location", location)
		w.Header().Set("Docker-Upload-UUID", uuid)
		w.Header().Set("Range", fmt.Sprintf("%d-%d", startRange, startRange+written-1))
		w.WriteHeader(http.StatusAccepted)
	}
}

// handleBlobs handles blob operations
func (s *Server) handleBlobs(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	digest := vars["digest"]
	if repository == "" || digest == "" {
		http.Error(w, "Repository or digest not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Handling blob request for repository: %s, digest: %s", repository, digest)

	switch r.Method {
	case http.MethodHead:
		s.handleBlobHead(w, r)
	case http.MethodGet:
		s.handleBlobGet(w, r)
	case http.MethodDelete:
		s.handleBlobDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleBlobHead handles HEAD requests for blobs
func (s *Server) handleBlobHead(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	digest := vars["digest"]
	if repository == "" || digest == "" {
		http.Error(w, "Repository or digest not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Handling HEAD request for blob %s in repository %s", digest, repository)
	path := filepath.Join(s.dataDir, "registry", "repositories", repository, "blobs", digest)
	log.Printf("DEBUG: Looking for blob at path: %s", path)

	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("DEBUG: Blob not found: %s", path)
			http.NotFound(w, r)
		} else {
			log.Printf("ERROR: Failed to stat blob: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Docker-Content-Digest", digest)
	w.WriteHeader(http.StatusOK)
}

// handleBlobGet handles GET requests for blobs
func (s *Server) handleBlobGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	digest := vars["digest"]
	if repository == "" || digest == "" {
		http.Error(w, "Repository or digest not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Handling GET request for blob %s in repository %s", digest, repository)
	path := filepath.Join(s.dataDir, "registry", "repositories", repository, "blobs", digest)
	log.Printf("DEBUG: Looking for blob at path: %s", path)

	// Open and serve the file
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("DEBUG: Blob not found: %s", path)
			http.NotFound(w, r)
		} else {
			log.Printf("ERROR: Failed to open blob: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		log.Printf("ERROR: Failed to stat blob: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Length", fmt.Sprintf("%d", info.Size()))
	w.Header().Set("Docker-Content-Digest", digest)
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, "", info.ModTime(), file)
}

// handleBlobDelete handles DELETE requests for blobs
func (s *Server) handleBlobDelete(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	digest := vars["digest"]
	if repository == "" || digest == "" {
		http.Error(w, "Repository or digest not found", http.StatusNotFound)
		return
	}

	path := filepath.Join(s.dataDir, "repositories", repository, "blobs", digest)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleManifests handles manifest operations
func (s *Server) handleManifests(w http.ResponseWriter, r *http.Request) {
	// Get repository and reference from URL
	vars := mux.Vars(r)
	repository := vars["repository"]
	reference := vars["reference"]
	if repository == "" || reference == "" {
		http.Error(w, "Repository or reference not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Handling manifest request for repository: %s, reference: %s", repository, reference)

	switch r.Method {
	case http.MethodHead:
		s.handleManifestHead(w, r)
	case http.MethodGet:
		s.handleManifestGet(w, r)
	case http.MethodPut:
		s.handleManifestPut(w, r)
	case http.MethodDelete:
		s.handleManifestDelete(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleManifestHead handles HEAD requests for manifests
func (s *Server) handleManifestHead(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: Handling manifest HEAD request for repository: %s, reference: %s", r.URL.Query().Get("repository"), r.URL.Query().Get("reference"))
	log.Printf("DEBUG: Accept header: %s", r.Header.Get("Accept"))

	path := filepath.Join(s.dataDir, "repositories", r.URL.Query().Get("repository"), "manifests", r.URL.Query().Get("reference"))

	// Check if manifest exists
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// If it's a symlink, resolve it
	if fi.Mode()&os.ModeSymlink != 0 {
		realPath, err := os.Readlink(path)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		path = filepath.Join(filepath.Dir(path), realPath)
		fi, err = os.Stat(path)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
	}

	// Read manifest
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Try to parse as V2 manifest first
	var manifest ManifestV2
	if err := json.Unmarshal(data, &manifest); err == nil {
		w.Header().Set("Content-Type", manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", filepath.Base(path))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.WriteHeader(http.StatusOK)
		return
	}

	// Try to parse as OCI index
	var index OCIIndex
	if err := json.Unmarshal(data, &index); err == nil {
		w.Header().Set("Content-Type", manifestOCIIndex)
		w.Header().Set("Docker-Content-Digest", filepath.Base(path))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.WriteHeader(http.StatusOK)
		return
	}

	// If we can't parse it as either, return an error
	http.Error(w, "Invalid manifest format", http.StatusBadRequest)
}

// handleManifestGet handles GET requests for manifests
func (s *Server) handleManifestGet(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	reference := vars["reference"]
	if repository == "" || reference == "" {
		http.Error(w, "Repository or reference not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Handling manifest GET request for repository: %s, reference: %s", repository, reference)
	log.Printf("DEBUG: Accept header: %s", r.Header.Get("Accept"))

	path, err := s.paths.GetManifestPath(repository, reference)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// First check if the file exists
	_, err = os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		log.Printf("ERROR: Failed to stat manifest file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Only try to resolve symlinks if the file exists
	resolvedPath, err := resolveSymlink(path, 10)
	if err != nil {
		log.Printf("ERROR: Failed to resolve manifest symlink: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Read manifest
	data, err := os.ReadFile(resolvedPath)
	if err != nil {
		log.Printf("ERROR: Failed to read manifest file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Try to parse as V2 manifest first
	var manifest ManifestV2
	if err := json.Unmarshal(data, &manifest); err == nil {
		w.Header().Set("Content-Type", manifest.MediaType)
		w.Header().Set("Docker-Content-Digest", filepath.Base(resolvedPath))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
		return
	}

	// Try to parse as OCI index
	var index OCIIndex
	if err := json.Unmarshal(data, &index); err == nil {
		w.Header().Set("Content-Type", manifestOCIIndex)
		w.Header().Set("Docker-Content-Digest", filepath.Base(resolvedPath))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Write(data)
		return
	}

	// If we can't parse it as either, return an error
	http.Error(w, "Invalid manifest format", http.StatusBadRequest)
}

// handleManifestPut handles PUT requests for manifests
func (s *Server) handleManifestPut(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	repository := vars["repository"]
	reference := vars["reference"]
	if repository == "" || reference == "" {
		http.Error(w, "Repository or reference not found", http.StatusNotFound)
		return
	}

	// Read manifest content
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("ERROR: Failed to read manifest content: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Calculate digest
	dgst := digest.FromBytes(body)

	// Get manifest path
	manifestPath, err := s.paths.GetManifestPath(repository, dgst.String())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create manifest directory
	if err := os.MkdirAll(filepath.Dir(manifestPath), 0755); err != nil {
		log.Printf("ERROR: Failed to create manifest directory: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Write manifest file with digest as filename
	if err := os.WriteFile(manifestPath, body, 0644); err != nil {
		log.Printf("ERROR: Failed to write manifest file: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Only create tag symlink if reference is not a digest
	if !strings.HasPrefix(reference, "sha256:") {
		if err := s.paths.CreateTag(repository, reference, dgst.String()); err != nil {
			log.Printf("ERROR: Failed to create tag symlink: %v", err)
			// Don't fail the whole operation if just the symlink fails
			// The manifest is already stored successfully
		} else {
			// Update in-memory manifest map
			s.mu.Lock()
			if tags, exists := s.manifest[repository]; exists {
				// Check if tag already exists
				found := false
				for _, tag := range tags {
					if tag == reference {
						found = true
						break
					}
				}
				if !found {
					s.manifest[repository] = append(tags, reference)
					sort.Strings(s.manifest[repository])
				}
			} else {
				s.manifest[repository] = []string{reference}
			}
			s.mu.Unlock()
		}
	}

	// Set response headers
	w.Header().Set("Docker-Content-Digest", dgst.String())
	location, err := s.paths.GetAPIPath(repository, fmt.Sprintf("manifests/%s", reference))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusCreated)
}

// contains checks if a string slice contains a value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// handleManifestDelete handles DELETE requests for manifests
func (s *Server) handleManifestDelete(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join(s.dataDir, "repositories", r.URL.Query().Get("repository"), "manifests", r.URL.Query().Get("reference"))
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
		} else {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	s.mu.Lock()
	if tags, exists := s.manifest[r.URL.Query().Get("repository")]; exists {
		newTags := make([]string, 0)
		for _, tag := range tags {
			if tag != r.URL.Query().Get("reference") {
				newTags = append(newTags, tag)
			}
		}
		s.manifest[r.URL.Query().Get("repository")] = newTags
	}
	s.mu.Unlock()

	w.WriteHeader(http.StatusNoContent)
}

// handleCatalog returns the list of repositories
func (s *Server) handleCatalog(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse pagination parameters
	n := 100 // Default limit
	if limit := r.URL.Query().Get("n"); limit != "" {
		if parsed, err := strconv.Atoi(limit); err == nil && parsed > 0 {
			n = parsed
		}
	}
	last := r.URL.Query().Get("last")

	// Get repositories directory path
	reposDir := filepath.Join(s.dataDir, storage.RepositoriesDir)

	var repositories []string
	err := filepath.Walk(reposDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		// Skip root directory
		if path == reposDir {
			return nil
		}

		// Only process manifest directories
		if !info.IsDir() || !strings.HasSuffix(path, "manifests") {
			return nil
		}

		// Get repository path relative to repositories directory
		relPath, err := filepath.Rel(reposDir, filepath.Dir(path))
		if err != nil {
			return err
		}

		// Skip if before last parameter
		if last != "" && relPath <= last {
			return nil
		}

		repositories = append(repositories, relPath)
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed to walk repositories directory: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Sort repositories for consistent output
	sort.Strings(repositories)

	// Apply pagination
	if len(repositories) > n {
		repositories = repositories[:n]
	}

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"repositories": repositories,
	})
}

// handleRepository handles repository operations
func (s *Server) handleRepository(w http.ResponseWriter, r *http.Request) {
	log.Printf("DEBUG: Handling repository request: %s %s", r.Method, r.URL.Path)

	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Get list of repositories
	var repositories []string
	err := filepath.Walk(s.dataDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Printf("WARNING: Error accessing path %s: %v", path, err)
			return nil
		}

		// Skip root directory
		if path == s.dataDir {
			return nil
		}

		// Skip if not a manifests directory
		if !strings.HasSuffix(path, "manifests") {
			return nil
		}

		// Skip if not a directory
		if !info.IsDir() {
			return nil
		}

		// Get repository name from parent directory
		repository := filepath.Base(filepath.Dir(path))
		repositories = append(repositories, repository)
		return nil
	})

	if err != nil {
		log.Printf("ERROR: Failed to walk data directory: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Sort repositories for consistent output
	sort.Strings(repositories)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string][]string{
		"repositories": repositories,
	})
}

// GetDataDir returns the data directory path
func (s *Server) GetDataDir() string {
	return s.dataDir
}

// GetHost returns the registry's host address
func (s *Server) GetHost() string {
	return fmt.Sprintf("https://0.0.0.0:%d", s.port)
}

// GetImageInfo returns information about all images in the registry
func (s *Server) GetImageInfo() ([]ImageInfo, error) {
	var images []ImageInfo
	repoPath := filepath.Join(s.dataDir, "registry", "repositories")

	err := filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				// No repositories yet
				return nil
			}
			return err
		}

		// Skip if not in manifests directory
		if !strings.Contains(path, "manifests") {
			return nil
		}

		// Skip if directory
		if info.IsDir() {
			return nil
		}

		// Get repository from path
		relPath, err := filepath.Rel(repoPath, path)
		if err != nil {
			return nil
		}

		parts := strings.Split(relPath, string(os.PathSeparator))
		if len(parts) < 3 {
			return nil
		}

		repository := parts[0]
		reference := parts[2]

		// Skip if not a manifest file (i.e., skip symlinks)
		if !strings.HasPrefix(reference, "sha256:") {
			return nil
		}

		log.Printf("DEBUG: Processing manifest for repository %s, reference %s", repository, reference)

		// Read manifest
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("WARNING: Error reading manifest file %s: %v", path, err)
			return nil
		}

		var manifest ManifestV2
		if err := json.Unmarshal(data, &manifest); err != nil {
			// Try parsing as OCI index
			var index OCIIndex
			if err := json.Unmarshal(data, &index); err != nil {
				log.Printf("WARNING: Error parsing manifest/index file %s: %v", path, err)
				return nil
			}
			// Handle OCI index
			for _, m := range index.Manifests {
				// Get the actual manifest for this platform
				manifestPath := filepath.Join(s.dataDir, "registry", "repositories", repository, "blobs", m.Digest)
				manifestData, err := os.ReadFile(manifestPath)
				if err != nil {
					log.Printf("WARNING: Error reading platform manifest %s: %v", m.Digest, err)
					continue
				}

				var platformManifest ManifestV2
				if err := json.Unmarshal(manifestData, &platformManifest); err != nil {
					log.Printf("WARNING: Error parsing platform manifest %s: %v", m.Digest, err)
					continue
				}

				// Calculate total size including config and layers
				var totalSize int64
				totalSize += platformManifest.Config.Size
				for _, layer := range platformManifest.Layers {
					totalSize += layer.Size
				}

				imageInfo := ImageInfo{
					Repository: repository,
					Name:       repository,
					Tag:        "latest", // Default to latest for now
					MediaType:  m.MediaType,
					Digest:     m.Digest,
					Size:       totalSize,
					Created:    info.ModTime(),
					Platform:   m.Platform,
				}

				// Copy layers from the platform manifest
				imageInfo.Layers = make([]LayerInfo, len(platformManifest.Layers))
				for i, layer := range platformManifest.Layers {
					imageInfo.Layers[i] = LayerInfo{
						MediaType: layer.MediaType,
						Digest:    layer.Digest,
						Size:      layer.Size,
					}
				}
				images = append(images, imageInfo)
			}
			return nil
		}

		// Calculate total size including all layers
		var totalSize int64
		totalSize += manifest.Config.Size
		for _, layer := range manifest.Layers {
			totalSize += layer.Size
		}

		// Find all tags pointing to this manifest
		tags := []string{}
		manifestsDir := filepath.Dir(path)
		tagFiles, err := os.ReadDir(manifestsDir)
		if err == nil {
			for _, file := range tagFiles {
				if file.Type()&os.ModeSymlink != 0 {
					linkPath := filepath.Join(manifestsDir, file.Name())
					target, err := os.Readlink(linkPath)
					if err == nil && filepath.Base(target) == reference {
						tags = append(tags, file.Name())
					}
				}
			}
		}

		// If no tags found, use digest as tag
		if len(tags) == 0 {
			tags = append(tags, strings.TrimPrefix(reference, "sha256:"))
		}

		// Create an ImageInfo for each tag
		for _, tag := range tags {
			imageInfo := ImageInfo{
				Repository: repository,
				Name:       repository,
				Tag:        tag,
				MediaType:  manifest.MediaType,
				Digest:     reference,
				Size:       totalSize,
				Created:    info.ModTime(),
			}

			// Copy layers
			imageInfo.Layers = make([]LayerInfo, len(manifest.Layers))
			for i, layer := range manifest.Layers {
				imageInfo.Layers[i] = LayerInfo{
					MediaType: layer.MediaType,
					Digest:    layer.Digest,
					Size:      layer.Size,
				}
			}

			images = append(images, imageInfo)
			log.Printf("DEBUG: Added image info for %s:%s", repository, tag)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking data directory: %v", err)
	}

	return images, nil
}

// DeleteImage deletes an image from the registry
func (s *Server) DeleteImage(repository, reference string) error {
	log.Printf("DEBUG: Deleting image %s:%s", repository, reference)

	// Validate repository name using the path manager
	if err := s.paths.ValidateRepository(repository); err != nil {
		return fmt.Errorf("failed to validate repository: %v", err)
	}

	// Construct the full path according to design
	fullManifestPath := filepath.Join(s.dataDir, "registry", "repositories", repository, "manifests", reference)
	log.Printf("DEBUG: Looking for manifest at: %s", fullManifestPath)

	// Check if it's a symlink and resolve it
	fi, err := os.Lstat(fullManifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %v", err)
	}

	// If it's a symlink, get the actual manifest path
	actualManifestPath := fullManifestPath
	if fi.Mode()&os.ModeSymlink != 0 {
		realPath, err := os.Readlink(fullManifestPath)
		if err != nil {
			return fmt.Errorf("failed to read symlink: %v", err)
		}
		actualManifestPath = filepath.Join(filepath.Dir(fullManifestPath), realPath)
	}

	// Check if other tags point to this manifest
	manifestDir := filepath.Dir(fullManifestPath)
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		return fmt.Errorf("failed to read manifest directory: %v", err)
	}

	// Count how many symlinks point to this manifest
	linkCount := 0
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			linkPath := filepath.Join(manifestDir, entry.Name())
			if linkPath == fullManifestPath {
				continue // Skip the tag we're deleting
			}
			target, err := os.Readlink(linkPath)
			if err != nil {
				log.Printf("WARNING: Failed to read symlink %s: %v", linkPath, err)
				continue
			}
			if filepath.Join(manifestDir, target) == actualManifestPath {
				linkCount++
			}
		}
	}

	// Delete the tag symlink
	log.Printf("DEBUG: Deleting tag symlink at: %s", fullManifestPath)
	if err := os.Remove(fullManifestPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete manifest symlink: %v", err)
	}

	// Only delete the manifest and layers if no other tags reference it
	if linkCount == 0 {
		log.Printf("DEBUG: No other tags reference this manifest, deleting manifest and layers")

		// Read manifest to get layer digests
		data, err := os.ReadFile(actualManifestPath)
		if err != nil {
			return fmt.Errorf("failed to read manifest: %v", err)
		}

		// Try to parse as V2 manifest first
		var manifest ManifestV2
		if err := json.Unmarshal(data, &manifest); err == nil {
			log.Printf("DEBUG: Found V2 manifest with %d layers", len(manifest.Layers))
			// Delete all layers
			for _, layer := range manifest.Layers {
				// Construct the full blob path according to design
				fullBlobPath := filepath.Join(s.dataDir, "registry", "repositories", repository, "blobs", layer.Digest)
				log.Printf("DEBUG: Deleting layer at: %s", fullBlobPath)
				if err := os.Remove(fullBlobPath); err != nil && !os.IsNotExist(err) {
					log.Printf("WARNING: Failed to delete layer %s: %v", layer.Digest, err)
				}
			}
		} else {
			// Try to parse as OCI index
			var index OCIIndex
			if err := json.Unmarshal(data, &index); err == nil {
				log.Printf("DEBUG: Found OCI index with %d manifests", len(index.Manifests))
				// Delete all manifests in the index
				for _, m := range index.Manifests {
					// Construct the full blob path according to design
					fullBlobPath := filepath.Join(s.dataDir, "registry", "repositories", repository, "blobs", m.Digest)
					log.Printf("DEBUG: Deleting manifest blob at: %s", fullBlobPath)
					if err := os.Remove(fullBlobPath); err != nil && !os.IsNotExist(err) {
						log.Printf("WARNING: Failed to delete manifest %s: %v", m.Digest, err)
					}
				}
			} else {
				return fmt.Errorf("invalid manifest format")
			}
		}

		// Delete the manifest file
		log.Printf("DEBUG: Deleting manifest file at: %s", actualManifestPath)
		if err := os.Remove(actualManifestPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete manifest: %v", err)
		}
	} else {
		log.Printf("DEBUG: Skipping manifest deletion as %d other tags reference it", linkCount)
	}

	// Update in-memory manifest map
	s.mu.Lock()
	if tags, exists := s.manifest[repository]; exists {
		newTags := make([]string, 0)
		for _, tag := range tags {
			if tag != reference {
				newTags = append(newTags, tag)
			}
		}
		s.manifest[repository] = newTags
	}
	s.mu.Unlock()

	log.Printf("DEBUG: Successfully deleted image %s:%s", repository, reference)
	return nil
}

// handleTagsList returns the list of tags for a repository
func (s *Server) handleTagsList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get repository from URL
	vars := mux.Vars(r)
	repository := vars["repository"]
	if repository == "" {
		http.Error(w, "Repository not found", http.StatusNotFound)
		return
	}

	log.Printf("DEBUG: Looking up tags for repository: %s", repository)

	// Get manifest directory path
	manifestDir, err := s.paths.GetRepositoryManifestsDir(repository)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Get list of tags from filesystem
	var tags []string
	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "Repository not found", http.StatusNotFound)
			return
		}
		log.Printf("ERROR: Failed to read manifests directory: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Collect tags from manifest directory
	for _, entry := range entries {
		// Skip directories and digest files
		if entry.IsDir() || strings.HasPrefix(entry.Name(), "sha256:") {
			continue
		}

		// Add tag to list
		tags = append(tags, entry.Name())
	}

	// Sort tags for consistent output
	sort.Strings(tags)

	// Update in-memory manifest map
	s.mu.Lock()
	s.manifest[repository] = tags
	s.mu.Unlock()

	// Write response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"name": repository,
		"tags": tags,
	})
}

// GetTags returns a map of repository names to their tags
func (s *Server) GetTags() map[string][]string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Create a copy of the manifest map
	tags := make(map[string][]string, len(s.manifest))
	for repo, repoTags := range s.manifest {
		tagsCopy := make([]string, len(repoTags))
		copy(tagsCopy, repoTags)
		tags[repo] = tagsCopy
	}

	return tags
}

// PurgeRegistry removes all data from the registry
func (s *Server) PurgeRegistry() error {
	log.Printf("DEBUG: Starting registry purge from directory: %s", s.dataDir)

	// Get the full registry path
	registryPath := filepath.Join(s.dataDir, "registry")

	// Remove all contents of the registry directory
	err := filepath.Walk(registryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				log.Printf("DEBUG: Path does not exist: %s", path)
				return nil
			}
			return err
		}
		if path == registryPath {
			return nil
		}
		log.Printf("DEBUG: Removing path: %s", path)
		return os.RemoveAll(path)
	})

	if err != nil {
		return fmt.Errorf("failed to purge registry: %v", err)
	}

	// Recreate necessary directories
	dirs := []string{
		filepath.Join(registryPath, "repositories"),
		filepath.Join(registryPath, "temp", "uploads"),
	}

	for _, dir := range dirs {
		log.Printf("DEBUG: Creating directory: %s", dir)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("failed to create directory %s: %v", dir, err)
		}
	}

	// Clear in-memory state
	s.mu.Lock()
	s.manifest = make(map[string][]string)
	s.uploads = make(map[string]string)
	s.mu.Unlock()

	log.Printf("DEBUG: Registry purge completed successfully")
	return nil
}

// GetPort returns the port number the registry is running on
func (s *Server) GetPort() int {
	return s.port
}

// handleAPIVersion returns the supported API versions
func (s *Server) handleAPIVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusOK)
}

// generateUUID generates a unique identifier for uploads
func generateUUID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// If it's a symlink, resolve it with a maximum depth to prevent infinite loops
func resolveSymlink(path string, maxDepth int) (string, error) {
	if maxDepth <= 0 {
		return "", fmt.Errorf("too many levels of symbolic links")
	}

	fi, err := os.Lstat(path)
	if err != nil {
		return "", err
	}

	if fi.Mode()&os.ModeSymlink == 0 {
		return path, nil
	}

	realPath, err := os.Readlink(path)
	if err != nil {
		return "", err
	}

	// If it's a relative path, make it relative to the symlink's directory
	if !filepath.IsAbs(realPath) {
		// Extract just the digest part if it's a full manifest path
		if strings.HasPrefix(realPath, "data/registry/repositories") {
			realPath = filepath.Base(realPath)
		}
		realPath = filepath.Join(filepath.Dir(path), realPath)
	}

	return resolveSymlink(realPath, maxDepth-1)
}

// scanExistingTags scans the registry directory and populates the manifest map with existing tags
func (s *Server) scanExistingTags() error {
	log.Printf("DEBUG: Scanning existing tags in registry")
	registryPath := filepath.Join(s.dataDir, "registry", "repositories")

	// Read repository directories
	repos, err := os.ReadDir(registryPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("DEBUG: No existing repositories found")
			return nil
		}
		return fmt.Errorf("failed to read registry directory: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Scan each repository
	for _, repo := range repos {
		if !repo.IsDir() {
			continue
		}
		repoName := repo.Name()
		manifestDir := filepath.Join(registryPath, repoName, "manifests")

		entries, err := os.ReadDir(manifestDir)
		if err != nil {
			log.Printf("WARNING: Failed to read manifests for repository %s: %v", repoName, err)
			continue
		}

		var tags []string
		for _, entry := range entries {
			// Skip directories and digest files
			if entry.IsDir() || strings.HasPrefix(entry.Name(), "sha256:") {
				continue
			}
			tags = append(tags, entry.Name())
		}

		if len(tags) > 0 {
			sort.Strings(tags)
			s.manifest[repoName] = tags
			log.Printf("DEBUG: Found %d tags for repository %s", len(tags), repoName)
		}
	}

	return nil
}
