<p align="center">
  <h1 align="center">XMap</h1>
  <p align="center">High-performance Distributed Network Service Fingerprinting Framework</p>
</p>

<p align="center">
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Made%20with-Go-1f425f.svg" alt="made-with-Go"></a>
  <a href="https://github.com/tongchengbin/xmap/releases"><img src="https://img.shields.io/github/release/tongchengbin/xmap.svg" alt="Release"></a>
  <a href="https://github.com/tongchengbin/xmap/issues"><img src="https://img.shields.io/github/issues/tongchengbin/xmap.svg" alt="Issues"></a>
  <a href="https://github.com/tongchengbin/xmap/blob/master/LICENSE"><img src="https://img.shields.io/github/license/tongchengbin/xmap.svg" alt="License"></a>
</p>

[中文文档](README.md) | [English](README_EN.md)

# XMap: High-performance Distributed Network Service Fingerprinting Framework

## Introduction

XMap is a high-performance distributed network service fingerprinting framework based on Go. It builds upon gonmap with architectural optimizations and feature extensions, focusing on providing more efficient and scalable network service identification capabilities. XMap is particularly suitable for use in large-scale distributed environments, supporting scenarios where multiple tasks share fingerprint libraries while using independent scanning parameters.

## 🌟 Key Features

- **High-performance scanning engine**: TCP/UDP service detection and identification optimized based on gonmap
- **Shared fingerprint library**: Multiple tasks share fingerprint loading, reducing memory usage and initialization time
- **Independent scanning parameters**: Each scanning task can use customized scanning parameters
- **Distributed architecture**: Support for horizontally scalable worker nodes
- **Flexible plugin system**: Support for custom detection and matching logic
- **Complete context control**: Support for timeout and cancellation mechanisms
- **Rich output formats**: Support for multiple output formats such as JSON, CSV, etc.
- **Real-time monitoring**: Provides real-time monitoring of scanning progress and resource usage
- **Web fingerprint identification**: Integrates appfinger for efficient Web application fingerprint identification
- **Beautiful output**: Provides Nuclei-like colored output format for enhanced user experience

## 🚀 Quick Start

### Installation

#### Using go install

```bash
# Install the latest version directly
go install github.com/tongchengbin/xmap@latest
```

#### From source code

```bash
# Clone the repository
git clone https://github.com/tongchengbin/xmap.git
cd xmap

# Install dependencies
go mod download

# Compile
go build -o xmap main.go

# Run
./xmap -h
```

#### Using Docker

```bash
# Build Docker image
docker build -t xmap .

# Run
docker run --rm xmap -h
```

### Basic Usage

```bash
# Scan a single target
xmap -t 192.168.1.1

# Scan multiple targets
xmap -t 192.168.1.1,192.168.1.2

# Scan multiple ports
xmap -t 192.168.1.1 -p 80,443,8080-8090

# Read targets from file
xmap -l targets.txt

# Use fast mode
xmap -t 192.168.1.1 -f

# Specify output format (console, json, csv)
xmap -t 192.168.1.1 -ot json

# Output results to file
xmap -t 192.168.1.1 -o results.json -ot json

# Show detailed logs
xmap -t 192.168.1.1 -v

# Update fingerprint rules
xmap -ur
```

### Programming Interface Example

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/tongchengbin/xmap/pkg/api"
	"github.com/tongchengbin/xmap/pkg/types"
)

func main() {
	// Create XMap instance
	xmap := api.NewXMap(
		api.WithTimeout(5*time.Second),
		api.WithRetries(2),
		api.WithVersionIntensity(7),
	)

	// Create scan target
	target := &types.ScanTarget{
		IP:       "192.168.1.1",
		Port:     80,
		Protocol: "tcp",
	}

	// Execute scan
	ctx := context.Background()
	
	// Use callback function to handle results
	scanOptions := &types.ScanOptions{
		Timeout:          5,
		VersionIntensity: 7,
	}
	
	err := xmap.ExecuteWithResultCallback(ctx, []*types.ScanTarget{target}, scanOptions,
		func(result *types.ScanResult) {
			// Process results
			fmt.Printf("IP: %s, Port: %d, Service: %s\n",
				result.Target.IP, result.Target.Port, result.Service)
			
			// Display component information
			for _, component := range result.Components {
				name, _ := component["name"]
				version, _ := component["version"]
				fmt.Printf("\tComponent: %v, Version: %v\n", name, version)
			}
		},
	)
	
	if err != nil {
		fmt.Printf("Scan failed: %v\n", err)
		return
	}
}
```

## 🏗️ Architecture Design

XMap adopts a modular design, primarily consisting of the following core components:

```
┌─────────────────────────────────────────────────────────────┐
│                      XMap Framework                          │
├─────────────┬─────────────┬───────────────┬─────────────────┤
│             │             │               │                 │
│  Fingerprint│   Scanner   │    Matcher    │     Worker      │
│   Manager   │   Engine    │     Engine    │      Pool       │
│             │             │               │                 │
├─────────────┼─────────────┼───────────────┼─────────────────┤
│             │             │               │                 │
│  Probe      │  Protocol   │   Result      │     Plugin      │
│  Repository │  Handlers   │   Processors  │     System      │
│             │             │               │                 │
└─────────────┴─────────────┴───────────────┴─────────────────┘
```

### Fingerprint Management Design

XMap implements a singleton pattern for FingerprintManager to ensure multiple tasks share the fingerprint library:

```go
// Get fingerprint manager singleton
func GetFingerprintManager(options *FingerprintOptions) *FingerprintManager {
    // Singleton implementation ensures fingerprint library is loaded only once
    // ...
    return fingerprintManagerInstance
}
```

### Scanning Engine Design

XMap provides a unified scanning interface, supporting both single and batch target scanning:

```go
// Scanner defines the scanner interface
type Scanner interface {
    // Execute single target scan
    Scan(ctx context.Context, target string, opts ...ScanOption) (*Result, error)
    
    // Execute batch target scan
    BatchScan(ctx context.Context, targets []string, opts ...ScanOption) ([]*Result, error)
}
```

### Worker Pool Design

To support efficient concurrent scanning, XMap implements a worker pool mechanism that can dynamically adjust concurrency as needed.

## 📋 Project Structure

```
xmap/
├── pkg/                      # Public packages
│   ├── api/                  # API interfaces
│   ├── model/                # Data models
│   ├── probe/                # Probe definitions
│   ├── scanner/              # Scanning engine
│   └── web/                  # Web scanning
├── examples/                 # Usage examples
│   ├── batch/                # Batch scanning examples
│   └── simple/               # Simple scanning examples
├── test/                     # Test code
├── main.go                   # Main program entry
├── go.mod                    # Go module definition
└── README.md                 # Project documentation
```

## ⚙️ Configuration Options

XMap provides a rich set of configuration options that can be set via command-line parameters or programming interface:

### Scanning Options

- **Timeout**: Connection timeout
- **ScanTimeout**: Total scan timeout
- **VersionIntensity**: Version detection intensity (0-9)
- **Concurrency**: Number of concurrent scans
- **Retries**: Number of retries
- **RetryInterval**: Retry interval
- **Proxy**: Proxy settings
- **EnableTLS**: Whether to enable TLS

### Fingerprint Options

- **ProbeFilePath**: Fingerprint file path
- **EnableCache**: Whether to enable caching
- **CacheTTL**: Cache expiry time
- **ReloadInterval**: Auto-reload interval

## 🔄 Differences from gonmap

XMap has made the following key improvements over gonmap:

1. **Fingerprint Management Optimization**:
   - Implements a singleton pattern fingerprint manager, sharing fingerprint libraries across multiple tasks
   - Supports fingerprint caching and automatic reload mechanisms

2. **Architecture Optimization**:
   - Modular design, decoupling scanning and matching logic
   - Unified scanning interface, simplifying calling methods

3. **Feature Enhancements**:
   - Worker pool implementation, supporting efficient concurrent scanning
   - Plugin system, supporting custom scanning and matching logic
   - More complete context control and error handling

4. **Performance Optimization**:
   - Reduces repeated fingerprint loading, lowering memory usage
   - Optimizes matching algorithms, improving identification speed
   - Supports priority scheduling of scanning tasks

5. **Web Scanning Enhancements**:
   - Integrates appfinger, providing efficient Web application fingerprint identification
   - Shared fingerprint library design, reducing memory usage

## 📝 License

XMap is licensed under the [MIT License](LICENSE).

## 🙏 Acknowledgements

XMap is based on the following open-source projects and resources:

- [rule](https://github.com/tongchengbin/finger-rules) - Provides service fingerprint identification rules
- [appfinger](https://github.com/tongchengbin/appfinger) - Provides Web application fingerprint identification capabilities
- [goflags](https://github.com/projectdiscovery/goflags) - Provides command-line argument parsing
- [gologger](https://github.com/projectdiscovery/gologger) - Provides logging functionality
