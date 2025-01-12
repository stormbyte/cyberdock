package storage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/opencontainers/go-digest"
)

// CreateBlobUpload creates a new blob upload
func (pm *PathManager) CreateBlobUpload(uuid string) (*os.File, error) {
	uploadPath := pm.GetUploadPath(uuid)
	if err := os.MkdirAll(filepath.Dir(uploadPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create upload directory: %v", err)
	}

	file, err := os.OpenFile(uploadPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to create upload file: %v", err)
	}

	return file, nil
}

// CompleteBlobUpload moves a completed upload to its final location
func (pm *PathManager) CompleteBlobUpload(repository, uuid string, dgst digest.Digest) error {
	uploadPath := pm.GetUploadPath(uuid)
	blobPath, err := pm.GetBlobPath(repository, dgst.String())
	if err != nil {
		return fmt.Errorf("failed to get blob path: %v", err)
	}

	// Create blob directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(blobPath), 0755); err != nil {
		return fmt.Errorf("failed to create blob directory: %v", err)
	}

	// Move the upload to its final location
	if err := os.Rename(uploadPath, blobPath); err != nil {
		return fmt.Errorf("failed to move blob: %v", err)
	}

	return nil
}

// DeleteBlob removes a blob file
func (pm *PathManager) DeleteBlob(repository string, dgst digest.Digest) error {
	blobPath, err := pm.GetBlobPath(repository, dgst.String())
	if err != nil {
		return fmt.Errorf("failed to get blob path: %v", err)
	}

	if err := os.Remove(blobPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete blob: %v", err)
	}

	return nil
}

// OpenBlob opens a blob for reading
func (pm *PathManager) OpenBlob(repository string, dgst digest.Digest) (*os.File, error) {
	blobPath, err := pm.GetBlobPath(repository, dgst.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get blob path: %v", err)
	}

	file, err := os.Open(blobPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open blob: %v", err)
	}

	return file, nil
}

// VerifyBlob verifies a blob's digest
func (pm *PathManager) VerifyBlob(repository string, dgst digest.Digest) error {
	file, err := pm.OpenBlob(repository, dgst)
	if err != nil {
		return err
	}
	defer file.Close()

	verifier := dgst.Verifier()
	if _, err := io.Copy(verifier, file); err != nil {
		return fmt.Errorf("failed to read blob: %v", err)
	}

	if !verifier.Verified() {
		return fmt.Errorf("blob digest verification failed")
	}

	return nil
}
