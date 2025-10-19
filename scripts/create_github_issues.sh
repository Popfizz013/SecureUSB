#!/bin/bash
# GitHub automation script for creating issues and managing project

set -e

# Configuration
REPO_OWNER="Popfizz013"
REPO_NAME="SecureUSB"
GITHUB_API="https://api.github.com"

# Check if GitHub CLI is installed
if ! command -v gh &> /dev/null; then
    echo "Error: GitHub CLI (gh) is required but not installed."
    echo "Install from: https://cli.github.com/"
    exit 1
fi

echo "GitHub automation script for SecureUSB"
echo "======================================="

# Function to create an issue
create_issue() {
    local title="$1"
    local body="$2"
    local labels="$3"
    
    echo "Creating issue: $title"
    
    if [ -n "$labels" ]; then
        gh issue create --title "$title" --body "$body" --label "$labels"
    else
        gh issue create --title "$title" --body "$body"
    fi
}

# Function to create development issues
create_development_issues() {
    echo "Creating development tracking issues..."
    
    # Core development issues
    create_issue "Implement GUI Interface" \
        "Develop a graphical user interface for SecureUSB using either tkinter or PyQt.

## Requirements
- [ ] Device selection interface
- [ ] Progress indicators for encryption/decryption
- [ ] Settings management
- [ ] System tray integration
- [ ] Cross-platform compatibility

## Acceptance Criteria
- GUI provides all CLI functionality
- Intuitive user experience
- Platform-native look and feel" \
        "enhancement,gui"

    create_issue "Add Multi-Factor Authentication" \
        "Implement additional authentication methods beyond passwords.

## Features to implement
- [ ] Hardware token support (YubiKey)
- [ ] Biometric authentication integration
- [ ] Time-based OTP (TOTP)
- [ ] Smart card support

## Technical Requirements
- Maintain backward compatibility
- Secure key storage
- Cross-platform support" \
        "enhancement,security"

    create_issue "Performance Optimization" \
        "Optimize encryption/decryption performance for large files.

## Optimization targets
- [ ] Streaming encryption for large files
- [ ] Multi-threaded processing
- [ ] Memory usage optimization
- [ ] Progress reporting improvements

## Performance goals
- Handle files >1GB efficiently
- Minimize memory footprint
- Maintain security standards" \
        "enhancement,performance"

    create_issue "Cross-Platform Testing" \
        "Ensure SecureUSB works correctly across all target platforms.

## Platforms to test
- [ ] Windows 10/11
- [ ] macOS 12+
- [ ] Ubuntu 20.04+
- [ ] Other Linux distributions

## Test areas
- USB detection accuracy
- File system compatibility
- Permission handling
- Performance benchmarks" \
        "testing,cross-platform"

    create_issue "Security Audit" \
        "Comprehensive security review of the SecureUSB implementation.

## Areas to review
- [ ] Cryptographic implementation
- [ ] Key derivation and storage
- [ ] Memory management
- [ ] Input validation
- [ ] Error handling

## Goals
- Identify potential vulnerabilities
- Ensure best practices compliance
- Document security architecture" \
        "security,audit"

    create_issue "Documentation Improvement" \
        "Enhance project documentation for users and developers.

## Documentation needs
- [ ] User manual with screenshots
- [ ] API documentation
- [ ] Security implementation guide
- [ ] Troubleshooting guide
- [ ] Development setup guide

## Target audiences
- End users
- Developers
- Security researchers" \
        "documentation"
}

# Function to create bug tracking issues
create_bug_issues() {
    echo "Creating bug tracking template..."
    
    create_issue "Bug Report Template" \
        "This is a template for reporting bugs in SecureUSB.

## Bug Description
A clear and concise description of what the bug is.

## Steps to Reproduce
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

## Expected Behavior
A clear and concise description of what you expected to happen.

## Actual Behavior
A clear and concise description of what actually happened.

## Environment
- OS: [e.g. Windows 10, Ubuntu 20.04]
- SecureUSB Version: [e.g. 0.1.0]
- Python Version: [e.g. 3.9.7]

## Additional Context
Add any other context about the problem here." \
        "bug,template"
}

# Main menu
show_menu() {
    echo ""
    echo "Available actions:"
    echo "1. Create development issues"
    echo "2. Create bug tracking template" 
    echo "3. List current issues"
    echo "4. Exit"
    echo ""
}

# Main loop
while true; do
    show_menu
    read -p "Select an action (1-4): " choice
    
    case $choice in
        1)
            create_development_issues
            echo "Development issues created successfully!"
            ;;
        2)
            create_bug_issues
            echo "Bug tracking template created successfully!"
            ;;
        3)
            echo "Current issues:"
            gh issue list
            ;;
        4)
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1-4."
            ;;
    esac
done