
<div align="center">
<table>
  <tr>
    <td>
      <img src="media/screen.png" alt="screenshot">
    </td>
    <td>
      <img src="media/charts.png" alt="charts">
    </td>
  </tr>
</table>
</div>

<div align="center">
  <h1>CyberDock</h1>
  <p><strong>Cyberpunk Docker Registry Interface</strong></p>
  <p>🐳 Docker Registry | 🌍 Web UI | ⚡ Fast | 🎨 Beautiful | 🔒 Secure</p>
  <p>
    <img src="https://img.shields.io/badge/version-0.3.0d-blue.svg" alt="Version 0.4.0">
    <img src="https://img.shields.io/badge/go-%3E%3D1.21-00ADD8.svg" alt="Go Version">
    <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20docker-brightgreen.svg" alt="Platform Support">
    <img src="https://img.shields.io/badge/license-GPLv3-green.svg" alt="License">
  </p>
</div>

CyberDock is a sleek, cyberpunk-themed Docker Registry with an integrated web interface. It combines a fully compliant OCI Distribution registry with a beautiful, real-time UI for managing your container images.

> The intention is to provide a simple, secure, and efficient way to replay and manage your Docker images.

## 🌟 Features

<table>
  <tr>
    <th>Registry Features</th>
    <th>Content Support</th>
  </tr>
  <tr>
    <td>
      <ul>
        <li>Full OCI Distribution Specification compliance</li>
        <li>Local filesystem storage with deduplication</li>
        <li>Efficient blob mounting between repositories</li>
        <li>Atomic operations for data integrity</li>
        <li>Automatic cleanup of incomplete uploads</li>
        <li>Real-time storage statistics</li>
        <li>Built-in garbage collection</li>
      </ul>
    </td>
    <td>
      <ul>
        <li>Docker V2 manifests and lists</li>
        <li>OCI manifests and image indexes</li>
        <li>Container configs</li>
        <li>Layer tarballs</li>
        <li>Cross-repository blob mounting</li>
        <li>Range request support</li>
        <li>🎉v0.2.0:Garbage collection</li>
      </ul>
    </td>
  </tr>
  <tr>
    <th>Web Interface</th>
    <th>Security</th>
  </tr>
  <tr>
    <td>
      <ul>
        <li>Cyberpunk-themed responsive design</li>
        <li>Real-time statistics and monitoring</li>
        <li>Image and tag management</li>
        <li>Storage efficiency tracking</li>
        <li>Layer analysis and visualization</li>
        <li>Search and filtering capabilities</li>
        <li>Secure HTTPS access</li>
      </ul>
    </td>
    <td>
      <ul>
        <li>Automatic TLS certificate generation</li>
        <li>Content verification through digests</li>
        <li>Proper file permissions</li>
        <li>Safe concurrent access</li>
        <li>Secure temporary file handling</li>
      </ul>
    </td>
  </tr>
</table>

## 🚀 Quick Start

### Docker

Docker image is a simple way to get started.
```bash
docker run -d --name cyberdock -p 5000:5000 -p 5001:5001 mattrogers/cyberdock:latest
```

1. Access the interfaces:
   - Registry: https://localhost:5000
   - Web UI: https://localhost:5001

If you have a mac 🍏 host and want to work around the port conflicts.
```bash
docker run -d --name cyberdock -p 5005:5000 -p 5006:5001 -mattrogers/cyberdock:latest
```

1. Access the interfaces:
   - Registry: https://localhost:5005
   - Web UI: https://localhost:5006

## 💻 Usage

CyberDock runs two servers:
- Registry server on port 5000
- Web UI server on port 5001

Remote Purge ☢️
```bash
curl -k -X POST https://cyberdock:5001/api/purge
```

### Docker Configuration

Add to your Docker daemon configuration:
```json
{
  "insecure-registries": ["localhost:5000"]
}
```

### Push Images
```bash
docker tag your-image:tag localhost:5000/your-image:tag
docker push localhost:5000/your-image:tag
```

### Pull Images
```bash
docker pull localhost:5000/your-image:tag
```

## 🔧 Configuration

Default ports:
- Registry: 5000
- Web UI: 5001

Command line flags:
```bash
-r PORT  # Set registry port (default: 5000)
-g PORT  # Set web UI port (default: 5001)
```

## ⚡️ Updates

- 0.3.0d:
  - Added storage efficiency analysis
  - Added image density metric
  - Added repository health metric
  - Added total layers and average layers per image metrics
  - Added layer distribution chart
  - Bugfixes for dashes and long names

<div align="center">
  <img src="media/screen.png" alt="screenshot">
  <img src="media/charts.png" alt="charts">


## ⚖️ License

<p>
CyberDock is licensed under the GNU General Public License v3.0 (GPLv3).<br>
<em>Free Software</em>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)

### Connect With Me 🤝

[![GitHub](https://img.shields.io/badge/GitHub-RamboRogers-181717?style=for-the-badge&logo=github)](https://github.com/RamboRogers)
[![Twitter](https://img.shields.io/badge/Twitter-@rogerscissp-1DA1F2?style=for-the-badge&logo=twitter)](https://x.com/rogerscissp)
[![Website](https://img.shields.io/badge/Web-matthewrogers.org-00ADD8?style=for-the-badge&logo=google-chrome)](https://matthewrogers.org)

</div>

