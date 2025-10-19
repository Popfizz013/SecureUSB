"""
File utilities for SecureUSB

Contains helper functions for file operations, logging, and hash verification.
"""

import os
import hashlib
import logging
import shutil
from pathlib import Path
from typing import Optional, List, Generator
import time


class FileUtils:
    """Utility class for file operations."""
    
    @staticmethod
    def setup_logging(verbose: bool = False, log_file: Optional[str] = None) -> logging.Logger:
        """
        Set up logging configuration.
        
        Args:
            verbose: Enable verbose logging
            log_file: Optional log file path
            
        Returns:
            Configured logger instance
        """
        log_level = logging.DEBUG if verbose else logging.INFO
        
        # Create logger
        logger = logging.getLogger('SecureUSB')
        logger.setLevel(log_level)
        
        # Clear any existing handlers
        logger.handlers.clear()
        
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        # File handler (optional)
        if log_file:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(log_level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        return logger
    
    @staticmethod
    def calculate_file_hash(file_path: Path, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of a file.
        
        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            
        Returns:
            Hex digest of the file hash
        """
        hash_func = hashlib.new(algorithm)
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        
        return hash_func.hexdigest()
    
    @staticmethod
    def verify_file_integrity(file_path: Path, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file integrity using hash comparison.
        
        Args:
            file_path: Path to the file
            expected_hash: Expected hash value
            algorithm: Hash algorithm used
            
        Returns:
            True if file integrity is verified, False otherwise
        """
        try:
            actual_hash = FileUtils.calculate_file_hash(file_path, algorithm)
            return actual_hash.lower() == expected_hash.lower()
        except (IOError, OSError):
            return False
    
    @staticmethod
    def safe_copy(source: Path, destination: Path, verify: bool = True) -> bool:
        """
        Safely copy a file with optional integrity verification.
        
        Args:
            source: Source file path
            destination: Destination file path  
            verify: Whether to verify copy integrity
            
        Returns:
            True if copy was successful, False otherwise
        """
        try:
            # Calculate source hash if verification is requested
            source_hash = None
            if verify:
                source_hash = FileUtils.calculate_file_hash(source)
            
            # Copy the file
            shutil.copy2(source, destination)
            
            # Verify copy if requested
            if verify and source_hash:
                return FileUtils.verify_file_integrity(destination, source_hash)
            
            return True
            
        except (IOError, OSError, shutil.Error):
            return False
    
    @staticmethod
    def secure_delete(file_path: Path, passes: int = 3) -> bool:
        """
        Securely delete a file by overwriting it multiple times.
        
        Args:
            file_path: Path to the file to delete
            passes: Number of overwrite passes
            
        Returns:
            True if deletion was successful, False otherwise
        """
        try:
            if not file_path.exists():
                return True
            
            file_size = file_path.stat().st_size
            
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                    f.flush()
                    os.fsync(f.fileno())
            
            # Finally delete the file
            file_path.unlink()
            return True
            
        except (IOError, OSError):
            return False
    
    @staticmethod
    def get_available_space(path: Path) -> int:
        """
        Get available disk space at the given path.
        
        Args:
            path: Path to check
            
        Returns:
            Available space in bytes
        """
        stat = shutil.disk_usage(path)
        return stat.free
    
    @staticmethod
    def find_files_by_pattern(directory: Path, pattern: str) -> Generator[Path, None, None]:
        """
        Find files matching a pattern in a directory.
        
        Args:
            directory: Directory to search
            pattern: File pattern to match
            
        Yields:
            Paths matching the pattern
        """
        for file_path in directory.rglob(pattern):
            if file_path.is_file():
                yield file_path
    
    @staticmethod
    def create_backup(file_path: Path, backup_suffix: str = '.backup') -> Optional[Path]:
        """
        Create a backup copy of a file.
        
        Args:
            file_path: Path to the original file
            backup_suffix: Suffix to add to backup filename
            
        Returns:
            Path to backup file if successful, None otherwise
        """
        backup_path = file_path.with_suffix(file_path.suffix + backup_suffix)
        
        if FileUtils.safe_copy(file_path, backup_path):
            return backup_path
        
        return None