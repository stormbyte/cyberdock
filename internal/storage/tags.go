package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CreateTag creates a tag symlink pointing to a manifest
func (pm *PathManager) CreateTag(repository, tag, digest string) error {
	if err := pm.ValidateRepository(repository); err != nil {
		return err
	}

	manifestsDir, err := pm.GetRepositoryManifestsDir(repository)
	if err != nil {
		return err
	}

	tagPath := filepath.Join(manifestsDir, tag)
	// Use just the digest filename for the symlink target
	target := digest

	// Remove existing tag if it exists
	if err := os.Remove(tagPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove existing tag: %v", err)
	}

	// Create the symlink using just the digest as the target
	if err := os.Symlink(target, tagPath); err != nil {
		return fmt.Errorf("failed to create tag symlink: %v", err)
	}

	return nil
}

// DeleteTag removes a tag symlink
func (pm *PathManager) DeleteTag(repository, tag string) error {
	tagPath, err := pm.GetManifestPath(repository, tag)
	if err != nil {
		return fmt.Errorf("failed to get tag path: %v", err)
	}

	if err := os.Remove(tagPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete tag: %v", err)
	}

	return nil
}

// GetTags returns a list of tags for a repository
func (pm *PathManager) GetTags(repository string) ([]string, error) {
	manifestDir, err := pm.GetManifestPath(repository, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get manifest directory: %v", err)
	}

	entries, err := os.ReadDir(manifestDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to read manifest directory: %v", err)
	}

	var tags []string
	for _, entry := range entries {
		// Skip directories and digest files
		if entry.IsDir() || strings.HasPrefix(entry.Name(), "sha256:") {
			continue
		}

		// Add tag to list
		tags = append(tags, entry.Name())
	}

	sort.Strings(tags)
	return tags, nil
}

// ResolveTag returns the digest that a tag points to
func (pm *PathManager) ResolveTag(repository, reference string) (string, error) {
	tagPath, err := pm.GetManifestPath(repository, reference)
	if err != nil {
		return "", fmt.Errorf("failed to get tag path: %v", err)
	}

	// If the reference is already a digest, return it
	if strings.HasPrefix(reference, "sha256:") {
		return reference, nil
	}

	// Read the symlink
	target, err := os.Readlink(tagPath)
	if err != nil {
		return "", fmt.Errorf("failed to read tag symlink: %v", err)
	}

	return target, nil
}
