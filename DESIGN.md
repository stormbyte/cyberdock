# CyberDock Design Document

## Core Components

1. Docker Registry Server
   - Implements OCI Distribution Specification
   - Handles blob storage and retrieval
   - Manages manifests and tags
   - Provides v2 API endpoints

2. Web UI Server
   - Provides web interface for registry management
   - Displays repository information
   - Allows image deletion and cleanup

## Storage Design

### Validated Implementation
The following structure has been implemented and validated through testing:
```
data/registry/
├── repositories/
│   └── {namespace}/{repository}/
│       ├── manifests/
│       │   ├── {tag} -> sha256:{digest}  # Symlinks to digest files
│       │   └── sha256:{digest}           # Manifest content files
│       └── blobs/
│           └── sha256:{digest}           # Layer blobs
└── temp/
    └── uploads/
        └── {uuid}/                       # Temporary upload directories
```

### Key Features
1. Repository Organization
   - Each repository has its own manifests and blobs directories
   - Blobs are stored under their respective repositories
   - Manifests are stored by digest with tag symlinks
   - Upload state managed in temporary directory

2. Tag Management
   - Tags implemented as symlinks to manifest digests
   - Tag updates preserve old manifests
   - Multiple tags can point to same manifest
   - Atomic tag updates via symlink operations

3. Blob Storage
   - Blobs stored by digest under repository
   - Content-addressable storage
   - Atomic blob uploads via temporary files
   - Proper cleanup of incomplete uploads

### Path Management Rules
1. Repository Paths
   - All repository paths must follow pattern: {namespace}/{name}
   - Repository names must follow Docker naming conventions
   - All components must be validated against allowed patterns
   - Path traversal must be prevented

2. Storage Organization
   - Each repository has its own manifests and blobs directories
   - All content is stored under repositories/{namespace}/{repository}/
   - Temporary uploads are isolated in temp/uploads/{uuid}/
   - Optional caching layer for frequently accessed content

3. Path Construction
   - Use path.Join for URL paths (forward slashes)
   - Use filepath.Join for filesystem paths (OS-specific separators)
   - Always validate path components before use
   - Use absolute paths within the registry root

4. File Operations
   - All file operations must be atomic
   - Create parent directories as needed
   - Handle concurrent access safely
   - Clean up temporary files reliably

## API Endpoints

### Registry API (v2)
1. Base Endpoint
   - GET /v2/ - API version check

2. Repository Operations
   - GET /v2/_catalog - List repositories
   - GET /v2/{repository}/tags/list - List repository tags

3. Manifest Operations
   - GET /v2/{repository}/manifests/{reference}
   - PUT /v2/{repository}/manifests/{reference}
   - DELETE /v2/{repository}/manifests/{reference}

4. Blob Operations
   - GET /v2/{repository}/blobs/{digest}
   - DELETE /v2/{repository}/blobs/{digest}
   - POST /v2/{repository}/blobs/uploads/
   - PATCH /v2/{repository}/blobs/uploads/{uuid}
   - PUT /v2/{repository}/blobs/uploads/{uuid}

### Content Types
1. Manifests
   - application/vnd.docker.distribution.manifest.v2+json
   - application/vnd.docker.distribution.manifest.list.v2+json
   - application/vnd.oci.image.manifest.v1+json
   - application/vnd.oci.image.index.v1+json

2. Layers
   - application/vnd.docker.image.rootfs.diff.tar.gzip
   - application/vnd.oci.image.layer.v1.tar+gzip

## Implementation Status

### Completed
- Basic registry server implementation
- Blob upload and download
- Manifest storage and retrieval
- Tag management
- Web UI for viewing repositories

### Next Steps
1. Path Management Refactoring
   - Implement centralized path management package
   - Add path validation and security checks
   - Update all handlers to use new path management
   - Add tests for path handling

2. Storage Consistency
   - Implement atomic operations for all file operations
   - Add consistency checks for manifests and blobs
   - Implement garbage collection for unused blobs
   - Add storage metrics and monitoring

3. Security Enhancements
   - Add path traversal prevention
   - Implement repository name validation
   - Add content validation for uploads
   - Implement access control lists

## Design Principles
1. Consistent Path Management
   - All paths must be constructed using the path management package
   - No direct string concatenation for paths
   - All paths must be validated before use
   - Clear separation between URL paths and filesystem paths

2. Data Integrity
   - All file operations must be atomic
   - Manifests must be validated before storage
   - Tags must always point to valid manifests
   - Blobs must be verified against their digests

3. Security
   - No path traversal vulnerabilities
   - Proper permission handling
   - Input validation for all user-provided data
   - Secure handling of temporary files

4. Performance
   - Efficient blob storage and retrieval
   - Proper handling of large uploads
   - Caching of frequently accessed data
   - Minimal filesystem operations

## Operation Flows

### Push Flow
1. Blob Upload Sequence
   - Client initiates upload with POST to /v2/{repository}/blobs/uploads/
   - Server creates UUID and temp directory in temp/uploads/{uuid}/
   - Client streams data with PATCH to /v2/{repository}/blobs/uploads/{uuid}
   - Client completes upload with PUT, providing digest
   - Server verifies digest and moves blob to repositories/{namespace}/{repository}/blobs/

2. Manifest Push Sequence
   - Client ensures all referenced blobs are uploaded
   - Client pushes manifest to /v2/{repository}/manifests/{tag}
   - Server validates manifest format and blob references
   - Server stores manifest in repositories/{namespace}/{repository}/manifests/
   - Server creates tag symlink pointing to manifest digest

### Pull Flow
1. Manifest Retrieval
   - Client requests manifest by tag or digest
   - Server resolves tag symlink if needed
   - Server returns manifest with content-type header
   - Client validates manifest format

2. Blob Download Sequence
   - Client extracts blob digests from manifest
   - Client requests each blob from /v2/{repository}/blobs/{digest}
   - Server locates blob in repository directory
   - Server streams blob data to client
   - Client verifies blob digest

### Error Recovery
1. Upload Recovery
   - Incomplete uploads cleaned up after timeout
   - Temporary directories removed during cleanup
   - Upload resumption supported via Range header

2. Download Recovery
   - Partial downloads supported via Range header
   - Missing blobs return 404 with error details
   - Corrupted blobs detected via digest verification

## Data Management

### Consistency Requirements
1. Blob Management
   - Blobs must be fully uploaded before manifest references them
   - Blob digests must be verified on upload and download
   - Duplicate blobs should be handled via hard links
   - Missing blobs must be reported clearly to clients

2. Manifest Management
   - Manifests must reference only existing blobs
   - Tag updates must be atomic
   - Old manifests preserved until garbage collection
   - Manifest format validated on push

3. Repository State
   - Repository listing must reflect actual content
   - Tag listing must match filesystem state
   - Broken symlinks must be detected and fixed
   - Repository names must be validated

### Maintenance Operations
1. Garbage Collection
   - Identify unreferenced blobs
   - Remove unlinked manifests
   - Clean up temporary uploads
   - Update space usage statistics

2. Health Checks
   - Verify blob/manifest consistency
   - Check for broken symlinks
   - Validate directory permissions
   - Monitor disk space usage

3. Data Recovery
   - Backup strategy for metadata
   - Repair procedures for common issues
   - Consistency check tools
   - Emergency procedures

## Operational Requirements

### Configuration
1. Server Settings
   - TLS certificate and key paths
   - Listen address and port
   - Root directory location
   - Log level and format

2. Storage Settings
   - Maximum blob size
   - Upload timeout duration
   - Garbage collection interval
   - Cache size limits

3. Security Settings
   - TLS requirements
   - Client certificate validation
   - Repository name restrictions
   - Rate limiting rules

### Startup Sequence
1. Initialization
   - Verify data directory exists
   - Create required subdirectories
   - Check directory permissions
   - Initialize path manager

2. Recovery
   - Check for incomplete uploads
   - Verify manifest integrity
   - Clean up temporary files
   - Rebuild indices if needed

3. Service Start
   - Load TLS certificates
   - Start HTTP server
   - Initialize API handlers
   - Begin maintenance routines

### Monitoring
1. Metrics
   - Storage usage by repository
   - Request latency statistics
   - Error rate tracking
   - Upload/download throughput

2. Health Status
   - Directory structure integrity
   - Symlink validity
   - Disk space availability
   - Server resource usage

3. Logging
   - Operation audit trail
   - Error reporting
   - Performance metrics
   - Security events