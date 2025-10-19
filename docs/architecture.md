# SecureUSB Architecture

## Overview

SecureUSB is a secure USB drive protection system that provides encryption and authentication for USB storage devices. The system is designed with a modular architecture to ensure maintainability, testability, and extensibility.

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Interface │    │  Core Services  │    │   Data Layer    │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ CLI Interface   │────│ Auth Manager    │────│ Metadata Store  │
│ GUI Interface   │    │ Crypto Engine   │    │ File System     │
│ (Future)        │    │ USB Detector    │    │ Device Storage  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Core Components

### 1. USB Detector (`usb_detector.py`)
- **Purpose**: Detect and enumerate USB devices connected to the system
- **Key Features**:
  - Cross-platform USB device detection using `psutil`
  - Device information retrieval (capacity, filesystem, mount points)
  - Real-time device monitoring capabilities
- **Dependencies**: `psutil`, `platform`

### 2. Crypto Engine (`crypto_engine.py`)
- **Purpose**: Handle all encryption and decryption operations
- **Key Features**:
  - AES-256 encryption in CBC mode with PKCS7 padding
  - Secure key derivation using PBKDF2
  - File and data encryption/decryption
  - Cryptographically secure random number generation
- **Dependencies**: `cryptography` library

### 3. Authentication Manager (`auth_manager.py`)
- **Purpose**: Manage user authentication and key derivation
- **Key Features**:
  - Password-based authentication
  - PBKDF2 key derivation with configurable iterations
  - Secure password input handling
  - Salt generation and management
- **Dependencies**: `hashlib`, `secrets`, `getpass`

### 4. Metadata Manager (`metadata.py`)
- **Purpose**: Store and retrieve device metadata and encryption information
- **Key Features**:
  - Device ownership tracking
  - Encryption metadata storage (salt, key hashes)
  - Timestamp management (creation, last access)
  - JSON-based metadata persistence
- **Dependencies**: `json`, `datetime`

### 5. File Utilities (`utils/file_utils.py`)
- **Purpose**: Provide common file operations and utilities
- **Key Features**:
  - Secure file operations (copy, delete, move)
  - File integrity verification using hashes
  - Logging configuration and management
  - Disk space monitoring
- **Dependencies**: `hashlib`, `shutil`, `logging`

## Data Flow

### Device Encryption Process
1. User connects USB device
2. `USBDetector` identifies the device
3. `AuthManager` prompts for password and creates authentication data
4. `MetadataManager` creates and stores device metadata
5. `CryptoEngine` encrypts device data using derived key
6. System updates metadata with encryption status

### Device Access Process
1. User connects encrypted USB device
2. `USBDetector` identifies the device
3. `MetadataManager` loads device metadata
4. `AuthManager` prompts for password and verifies against stored data
5. `CryptoEngine` decrypts device data using derived key
6. System provides access to decrypted data

## Security Design

### Encryption
- **Algorithm**: AES-256 in CBC mode
- **Key Derivation**: PBKDF2 with SHA-256, 100,000 iterations
- **Initialization Vectors**: Cryptographically secure random IVs for each operation
- **Padding**: PKCS7 padding for block alignment

### Authentication
- **Password Requirements**: Minimum 8 characters
- **Salt Generation**: 32-byte cryptographically secure random salts
- **Key Storage**: Only salted hash derivatives stored, never plain keys
- **Timing Attack Protection**: Constant-time comparison for password verification

### Metadata Security
- **Owner Identification**: Unique owner IDs for device association
- **Timestamp Tracking**: Creation and access time logging
- **Integrity Protection**: Hash-based verification of metadata files
- **Storage Location**: Configurable metadata storage directory

## File Structure Mapping

```
src/
├── __init__.py                 # Package initialization
├── main.py                     # Application entry point
├── usb_detector.py             # USB detection and enumeration
├── crypto_engine.py            # Encryption/decryption operations  
├── auth_manager.py             # Authentication and key management
├── metadata.py                 # Device metadata management
├── ui/                         # User interface components
│   ├── __init__.py
│   └── cli_interface.py        # Command-line interface
└── utils/                      # Utility functions
    ├── __init__.py
    └── file_utils.py           # File operations and logging
```

## Extension Points

### Future Enhancements
1. **GUI Interface**: Desktop application using tkinter or PyQt
2. **Web Interface**: Browser-based management interface
3. **Mobile Support**: Android/iOS companion apps
4. **Cloud Integration**: Remote key backup and recovery
5. **Multi-Factor Authentication**: Hardware token or biometric support
6. **Enterprise Features**: Centralized policy management

### Plugin Architecture
The system can be extended with plugins for:
- Additional encryption algorithms
- Alternative authentication methods
- Custom metadata storage backends
- Device-specific optimizations
- Compliance and audit logging

## Performance Considerations

### Optimization Strategies
- **Streaming Encryption**: Process large files in chunks to minimize memory usage
- **Parallel Processing**: Multi-threaded encryption for improved performance
- **Caching**: In-memory caching of frequently accessed metadata
- **Lazy Loading**: Load device information only when needed

### Scalability
- **Multiple Devices**: Support for managing multiple encrypted USB devices
- **Concurrent Operations**: Thread-safe operations for simultaneous device access
- **Resource Management**: Efficient memory and CPU usage patterns

## Testing Strategy

### Unit Tests
- Individual component testing with mocked dependencies
- Cryptographic function verification
- Error condition testing
- Edge case handling

### Integration Tests
- End-to-end encryption/decryption workflows
- Cross-platform compatibility testing
- Performance benchmarking
- Security vulnerability assessment

### Test Coverage
- Target 90%+ code coverage
- Critical path testing for security functions
- Regression testing for bug fixes
- Automated testing in CI/CD pipeline