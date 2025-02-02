package ui

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cyberdock/internal/registry"
	"github.com/gorilla/mux"
)

//go:embed web/templates/index.html
var templateFS embed.FS

//go:embed web/static
var staticFS embed.FS

// Server represents the UI server
type Server struct {
	port      int
	cert      []byte
	key       []byte
	certFile  string
	keyFile   string
	registry  *registry.Server
	diskUsage DiskUsage
	router    *mux.Router
	version   string
}

// DiskUsage represents registry storage statistics
type DiskUsage struct {
	Size              int64     `json:"size"`
	FreeSpace         int64     `json:"freeSpace"`
	LastCheck         time.Time `json:"lastCheck"`
	TotalImages       int       `json:"totalImages"`
	TotalTags         int       `json:"totalTags"`
	StorageEfficiency float64   `json:"storageEfficiency"`
}

// NewServer creates a new UI server instance
func NewServer(cert, key []byte, certFile, keyFile string, port int, registry *registry.Server, version string) *Server {
	return &Server{
		port:     port,
		cert:     cert,
		key:      key,
		certFile: certFile,
		keyFile:  keyFile,
		registry: registry,
		router:   mux.NewRouter(),
		version:  version,
	}
}

// Start initializes and starts the UI server
func (s *Server) Start() error {
	// Initialize router
	s.router = mux.NewRouter()

	// UI routes
	s.router.HandleFunc("/", s.handleUI)
	s.router.HandleFunc("/static/{type}/{file}", s.handleStatic)

	// API routes
	s.router.HandleFunc("/api/images", s.handleImages)
	s.router.HandleFunc("/api/images/{repository}/{reference}", s.handleImages)
	s.router.HandleFunc("/api/tags", s.handleTags)
	s.router.HandleFunc("/api/purge", s.handlePurge)
	s.router.HandleFunc("/api/disk-usage", s.handleDiskUsage)

	// Start monitoring disk usage
	go s.monitorDiskUsage()

	// Start server
	log.Printf("Starting UI server on port %d", s.port)
	return http.ListenAndServeTLS(fmt.Sprintf(":%d", s.port), s.certFile, s.keyFile, s.router)
}

// handleUI serves the main UI page
func (s *Server) handleUI(w http.ResponseWriter, r *http.Request) {
	// Create template functions map
	funcMap := template.FuncMap{
		"formatSize": func(size int64) string {
			const unit = 1024
			if size < unit {
				return fmt.Sprintf("%d B", size)
			}
			div, exp := int64(unit), 0
			for n := size / unit; n >= unit; n /= unit {
				div *= unit
				exp++
			}
			return fmt.Sprintf("%.2f %cB", float64(size)/float64(div), "KMGTPE"[exp])
		},
		"mul": func(a, b float64) float64 {
			return a * b
		},
		"div": func(a, b int) float64 {
			if b == 0 {
				return 0
			}
			return float64(a) / float64(b)
		},
	}

	tmpl, err := template.New("index.html").Funcs(funcMap).ParseFS(templateFS, "web/templates/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Failed to parse template: %v", err)
		return
	}

	// Get registry host from request
	host := r.Host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	registryHost := fmt.Sprintf("https://%s:%d", host, s.registry.GetPort())

	data := struct {
		Title        string
		DiskUsage    DiskUsage
		LastUpdate   time.Time
		Version      string
		RegistryHost string
	}{
		Title:        "CyberDock Registry",
		DiskUsage:    s.diskUsage,
		LastUpdate:   s.diskUsage.LastCheck,
		Version:      s.version,
		RegistryHost: registryHost,
	}

	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("Failed to execute template: %v", err)
	}
}

// handleImages handles image-related API requests
func (s *Server) handleImages(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	switch r.Method {
	case http.MethodGet:
		// Get image information directly from registry
		images, err := s.registry.GetImageInfo()
		if err != nil {
			log.Printf("ERROR: Failed to get image info: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Debug log the images data
		for _, img := range images {
			log.Printf("DEBUG: Image data - Repository: %s, Tag: %s, Size: %d, Created: %v",
				img.Repository, img.Tag, img.Size, img.Created)
		}

		if err := json.NewEncoder(w).Encode(images); err != nil {
			log.Printf("ERROR: Failed to encode image info: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case http.MethodDelete:
		vars := mux.Vars(r)
		repository := vars["repository"]
		reference := vars["reference"]

		if repository == "" || reference == "" {
			log.Printf("ERROR: Missing repository or reference in delete request")
			http.Error(w, "Repository and reference are required", http.StatusBadRequest)
			return
		}

		log.Printf("DEBUG: Deleting image %s:%s", repository, reference)

		// Delete image directly through registry
		if err := s.registry.DeleteImage(repository, reference); err != nil {
			log.Printf("ERROR: Failed to delete image: %v", err)
			http.Error(w, fmt.Sprintf("Failed to delete image: %v", err), http.StatusInternalServerError)
			return
		}

		log.Printf("DEBUG: Successfully deleted image %s:%s", repository, reference)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleTags handles requests for repository tags
func (s *Server) handleTags(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("DEBUG: Getting tags from registry")
	tags := s.registry.GetTags()
	log.Printf("DEBUG: Found tags: %+v", tags)

	// Return empty object if no tags
	if len(tags) == 0 {
		w.Write([]byte("{}"))
		return
	}

	json.NewEncoder(w).Encode(tags)
}

// handlePurge handles registry purge requests
func (s *Server) handlePurge(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		log.Printf("ERROR: Invalid method for purge: %s", r.Method)
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Printf("DEBUG: Starting registry purge")
	if err := s.registry.PurgeRegistry(); err != nil {
		log.Printf("ERROR: Failed to purge registry: %v", err)
		http.Error(w, fmt.Sprintf("Failed to purge registry: %v", err), http.StatusInternalServerError)
		return
	}

	// Update disk usage after purge
	log.Printf("DEBUG: Updating disk usage after purge")
	s.updateDiskUsage()

	// Return success response
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Registry purged successfully",
	})
	log.Printf("DEBUG: Registry purge completed successfully")
}

// handleDiskUsage returns the current disk usage statistics
func (s *Server) handleDiskUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get current disk usage stats
	if err := s.updateDiskUsage(); err != nil {
		log.Printf("ERROR: Failed to update disk usage: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return the stats as JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.diskUsage)
}

// updateDiskUsage updates the current disk usage and statistics
func (s *Server) updateDiskUsage() error {
	var size int64
	var uniqueBlobSize int64
	uniqueBlobs := make(map[string]bool)

	// Walk through the data directory to calculate total size
	registryPath := filepath.Join(s.registry.GetDataDir(), "registry")
	err := filepath.Walk(registryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			size += info.Size()
			// Track unique blobs for storage efficiency
			if strings.Contains(path, "/blobs/") {
				uniqueBlobs[path] = true
				uniqueBlobSize += info.Size()
			}
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk data directory: %v", err)
	}

	// Get free space information
	var freeSpace int64
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(registryPath, &statfs); err != nil {
		log.Printf("WARNING: Failed to get free space: %v", err)
		freeSpace = 0
	} else {
		// Available blocks * block size
		freeSpace = int64(statfs.Bavail) * int64(statfs.Bsize)
	}

	// Calculate storage efficiency
	var efficiency float64
	if size > 0 {
		// Invert the efficiency calculation so higher means better deduplication
		// 1.0 (100%) means maximum deduplication, 0.0 (0%) means no deduplication
		efficiency = 1.0 - (float64(uniqueBlobSize) / float64(size))
	}

	// Get total images and tags
	images, err := s.registry.GetImageInfo()
	if err != nil {
		return fmt.Errorf("failed to get image info: %v", err)
	}

	totalTags := 0
	for _, img := range images {
		if img.Tag != "" {
			totalTags++
		}
	}

	// Update disk usage stats
	s.diskUsage = DiskUsage{
		Size:              size,
		FreeSpace:         freeSpace,
		LastCheck:         time.Now(),
		TotalImages:       len(images),
		TotalTags:         totalTags,
		StorageEfficiency: efficiency,
	}

	return nil
}

// countTotalTags counts the total number of tags across all images
func countTotalTags(images []registry.ImageInfo) int {
	tagCount := 0
	seenTags := make(map[string]bool)

	for _, img := range images {
		key := fmt.Sprintf("%s:%s", img.Repository, img.Tag)
		if !seenTags[key] {
			tagCount++
			seenTags[key] = true
		}
	}

	return tagCount
}

// monitorDiskUsage periodically updates the disk usage information
func (s *Server) monitorDiskUsage() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		// Update all disk usage statistics
		s.updateDiskUsage()

		<-ticker.C
	}
}

// handleStatic serves static files from the embedded filesystem
func (s *Server) handleStatic(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	fileType := vars["type"]
	fileName := vars["file"]

	// Construct the path to the static file
	filePath := fmt.Sprintf("web/static/%s/%s", fileType, fileName)

	// Get the file from the embedded filesystem
	content, err := staticFS.ReadFile(filePath)
	if err != nil {
		log.Printf("ERROR: Failed to read static file %s: %v", filePath, err)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Set content type based on file extension
	switch {
	case strings.HasSuffix(fileName, ".css"):
		w.Header().Set("Content-Type", "text/css")
	case strings.HasSuffix(fileName, ".js"):
		w.Header().Set("Content-Type", "application/javascript")
	case strings.HasSuffix(fileName, ".png"):
		w.Header().Set("Content-Type", "image/png")
	case strings.HasSuffix(fileName, ".svg"):
		w.Header().Set("Content-Type", "image/svg+xml")
	}

	// Write the file content
	w.Write(content)
}
