#!/usr/bin/env python3
"""
DNS Monitor Python Wrapper
==========================

This module provides a Python interface to the high-performance C++ DNS monitoring
system using ctypes. It allows Python applications to control the DNS monitor
while maintaining the performance benefits of native C++ code.

Usage Example:
    python3 dns_monitor_wrapper.py config.json

Features:
- Load C++ shared library via ctypes
- Control DNS monitoring (start/stop)
- Retrieve real-time statistics
- Graceful error handling and cleanup
"""

import ctypes
import ctypes.util
import time
import signal
import sys
import json
from typing import Optional, Tuple


class DNSMonitorWrapper:
    """
    Python wrapper for C++ DNS Monitor using ctypes.
    
    This class provides a Pythonic interface to the C++ DNS monitoring
    system while maintaining high performance through native code execution.
    """
    
    def __init__(self, library_path: Optional[str] = None):
        """
        Initialize the DNS Monitor wrapper.
        
        Args:
            library_path: Path to the compiled C++ library. If None, will attempt
                         to find the library automatically.
        """
        self._lib = None
        self._monitor = None
        self._load_library(library_path)
        self._configure_functions()
    
    def _load_library(self, library_path: Optional[str]):
        """Load the C++ DNS monitor shared library."""
        if library_path:
            self._lib = ctypes.CDLL(library_path)
        else:
            # Try to find the library automatically
            possible_paths = [
                "./build/lib/libdns_monitor.so",
                "./libdns_monitor.so",
                "/usr/local/lib/libdns_monitor.so",
                "/usr/lib/libdns_monitor.so"
            ]
            
            for path in possible_paths:
                try:
                    self._lib = ctypes.CDLL(path)
                    print(f"Loaded DNS monitor library from: {path}")
                    break
                except OSError:
                    continue
            
            if not self._lib:
                raise RuntimeError("Could not find DNS monitor library. Please compile the C++ code first.")
    
    def _configure_functions(self):
        """Configure ctypes function signatures for C++ interface."""
        # create_dns_monitor(const char* config_path) -> DNSMonitor*
        self._lib.create_dns_monitor.argtypes = [ctypes.c_char_p]
        self._lib.create_dns_monitor.restype = ctypes.c_void_p
        
        # destroy_dns_monitor(DNSMonitor* monitor) -> void
        self._lib.destroy_dns_monitor.argtypes = [ctypes.c_void_p]
        self._lib.destroy_dns_monitor.restype = None
        
        # start_monitoring(DNSMonitor* monitor) -> bool
        self._lib.start_monitoring.argtypes = [ctypes.c_void_p]
        self._lib.start_monitoring.restype = ctypes.c_bool
        
        # stop_monitoring(DNSMonitor* monitor) -> void
        self._lib.stop_monitoring.argtypes = [ctypes.c_void_p]
        self._lib.stop_monitoring.restype = None
        
        # get_statistics(DNSMonitor* monitor, uint64_t* total, uint64_t* dns, uint64_t* uploaded) -> void
        self._lib.get_statistics.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(ctypes.c_uint64)
        ]
        self._lib.get_statistics.restype = None
    
    def create_monitor(self, config_path: str) -> bool:
        """
        Create a new DNS monitor instance with the given configuration.
        
        Args:
            config_path: Path to JSON configuration file
            
        Returns:
            True if monitor was created successfully, False otherwise
        """
        if self._monitor:
            self.destroy_monitor()
        
        config_bytes = config_path.encode('utf-8')
        self._monitor = self._lib.create_dns_monitor(config_bytes)
        
        if not self._monitor:
            print("Failed to create DNS monitor instance")
            return False
        
        print(f"DNS monitor created with config: {config_path}")
        return True
    
    def start_monitoring(self) -> bool:
        """
        Start DNS monitoring operations.
        
        Returns:
            True if monitoring started successfully, False otherwise
        """
        if not self._monitor:
            print("No monitor instance available. Call create_monitor() first.")
            return False
        
        success = self._lib.start_monitoring(self._monitor)
        if success:
            print("DNS monitoring started successfully")
        else:
            print("Failed to start DNS monitoring")
        
        return success
    
    def stop_monitoring(self):
        """Stop DNS monitoring operations."""
        if self._monitor:
            self._lib.stop_monitoring(self._monitor)
            print("DNS monitoring stopped")
    
    def get_statistics(self) -> Tuple[int, int, int]:
        """
        Get current monitoring statistics.
        
        Returns:
            Tuple of (total_packets, dns_packets, uploaded_queries)
        """
        if not self._monitor:
            return (0, 0, 0)
        
        total = ctypes.c_uint64()
        dns = ctypes.c_uint64()
        uploaded = ctypes.c_uint64()
        
        self._lib.get_statistics(self._monitor, 
                                ctypes.byref(total),
                                ctypes.byref(dns),
                                ctypes.byref(uploaded))
        
        return (total.value, dns.value, uploaded.value)
    
    def destroy_monitor(self):
        """Clean up and destroy the DNS monitor instance."""
        if self._monitor:
            self._lib.destroy_dns_monitor(self._monitor)
            self._monitor = None
            print("DNS monitor instance destroyed")
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with cleanup."""
        self.stop_monitoring()
        self.destroy_monitor()


def signal_handler(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\nReceived interrupt signal. Shutting down gracefully...")
    sys.exit(0)


def print_statistics(monitor: DNSMonitorWrapper):
    """Print formatted statistics."""
    total, dns, uploaded = monitor.get_statistics()
    print(f"\rStats - Total: {total:,} | DNS: {dns:,} | Uploaded: {uploaded:,}", end='')


def main():
    """Main application entry point."""
    if len(sys.argv) != 2:
        print("Usage: python3 dns_monitor_wrapper.py <config.json>")
        print("\nExample:")
        print("  python3 dns_monitor_wrapper.py device/config.json")
        sys.exit(1)
    
    config_path = sys.argv[1]
    
    # Check if config file exists
    try:
        with open(config_path, 'r') as f:
            config = json.load(f)
            print(f"Configuration loaded: {config}")
    except FileNotFoundError:
        print(f"Error: Configuration file not found: {config_path}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in configuration file: {e}")
        sys.exit(1)
    
    # Set up signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)
    
    print("DNS Monitor Python Wrapper")
    print("=" * 40)
    
    try:
        with DNSMonitorWrapper() as monitor:
            # Create and start monitoring
            if not monitor.create_monitor(config_path):
                sys.exit(1)
            
            if not monitor.start_monitoring():
                sys.exit(1)
            
            print("Monitoring DNS traffic... (Press Ctrl+C to stop)")
            print("Statistics will update every 5 seconds:")
            print()
            
            # Monitor loop with statistics display
            try:
                while True:
                    print_statistics(monitor)
                    time.sleep(5)
                    
            except KeyboardInterrupt:
                print("\nShutdown requested...")
                
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    print("DNS Monitor stopped successfully")


if __name__ == "__main__":
    main()
