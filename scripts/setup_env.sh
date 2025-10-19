#!/bin/bash
# Environment setup script for SecureUSB

set -e  # Exit on any error

echo "Setting up SecureUSB development environment..."

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not installed."
    exit 1
fi

echo "Python version: $(python3 --version)"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate || source venv/Scripts/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "Installing dependencies..."
if [ -f "requirements.txt" ]; then
    pip install -r requirements.txt
else
    echo "Warning: requirements.txt not found"
fi

# Install development dependencies
echo "Installing development dependencies..."
pip install pytest pytest-cov black mypy flake8

echo "Environment setup complete!"
echo ""
echo "To activate the environment, run:"
echo "  source venv/bin/activate  (Linux/macOS)"
echo "  source venv/Scripts/activate  (Windows/Git Bash)"
echo ""
echo "To run tests:"
echo "  pytest tests/"
echo ""
echo "To run the CLI:"
echo "  python src/main.py --help"