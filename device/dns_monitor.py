#!/usr/bin/env python3
"""
Python wrapper for the high-performance C++ DNS monitor.
This provides a Python interface to the C++ packet capture engine.
"""

import asyncio
import json
import logging
import socket
import psutil
from typing import Dict, Optional
from pathlib import Path

try:
    import dns_monitor_cpp
except ImportError:
    print("C++ DNS monitor module not available. Please compile the C++ module first.")
    print("Run: cd dns_monitor && mkdir build && cd build && cmake .. && make")
    dns_monitor_cpp = None

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSFirewallDevice:
    """Python wrapper for the C++ DNS monitoring engine"""
    
    def __init__(self, config_path: str = "device/config.json"):
        self.config_path = config_path
        self.config = self.load_config(config_path)
        self.cpp_monitor = None
        self.is_running = False
        
        # Ensure C++ module is available
        if dns_monitor_cpp is None:
            raise RuntimeError("C++ DNS monitor module not available")
    
    def load_config(self, config_path: str) -> Dict:
        """Load device configuration"""
        config_file = Path(config_path)
        
        if config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        # Return default config
        return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'device_id': self.get_device_id(),
            'api_url': 'http://localhost:8000/api',
            'api_token': '',
            'monitor_interface': self.get_default_interface(),
            'log_level': 'INFO',
            'threat_threshold': 0.7,
            'upload_batch_size': 100,
            'upload_interval_seconds': 30
        }
    
    def get_device_id(self) -> str:
        """Generate unique device ID based on MAC address"""
        try:
            # Get MAC address of the first network interface
            interfaces = psutil.net_if_addrs()
            for interface_name, interface_addresses in interfaces.items():
                for address in interface_addresses:
                    if address.family == psutil.AF_LINK and not address.address.startswith('00:00:00'):
                        return f"device_{address.address.replace(':', '')}"
        except Exception:
            pass
        
        # Fallback to hostname
        return f"device_{socket.gethostname()}"
    
    def get_default_interface(self) -> str:
        """Get the default network interface"""
        try:
            # Try to find the main network interface
            interfaces = psutil.net_if_stats()
            for interface_name, stats in interfaces.items():
                if stats.isup and not interface_name.startswith(('lo', 'docker', 'br-')):
                    return interface_name
        except Exception:
            pass
        
        # Default fallbacks
        return 'eth0'
    
    def start(self):
        """Start the DNS monitoring"""
        if self.is_running:
            logger.warning("DNS monitor is already running")
            return
        
        try:
            # Create C++ configuration
            cpp_config = dns_monitor_cpp.DeviceConfig()
            cpp_config.device_id = self.config['device_id']
            cpp_config.api_url = self.config['api_url']
            cpp_config.api_token = self.config.get('api_token', '')
            cpp_config.monitor_interface = self.config['monitor_interface']
            cpp_config.log_level = self.config.get('log_level', 'INFO')
            cpp_config.threat_threshold = self.config.get('threat_threshold', 0.7)
            cpp_config.upload_batch_size = self.config.get('upload_batch_size', 100)
            cpp_config.upload_interval_seconds = self.config.get('upload_interval_seconds', 30)
            
            # Create C++ monitor
            self.cpp_monitor = dns_monitor_cpp.DNSMonitor(cpp_config)
            
            # Initialize and start
            if not self.cpp_monitor.initialize():
                raise RuntimeError("Failed to initialize C++ DNS monitor")
            
            self.cpp_monitor.start()
            self.is_running = True
            
            logger.info(f"DNS Monitor started on interface: {self.config['monitor_interface']}")
            
        except Exception as e:
            logger.error(f"Error starting DNS monitor: {e}")
            raise
    
    def stop(self):
        """Stop the DNS monitoring"""
        if not self.is_running:
            return
        
        try:
            if self.cpp_monitor:
                self.cpp_monitor.stop()
                self.cpp_monitor = None
            
            self.is_running = False
            logger.info("DNS Monitor stopped")
            
        except Exception as e:
            logger.error(f"Error stopping DNS monitor: {e}")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics"""
        if not self.cpp_monitor:
            return {
                'total_packets': 0,
                'dns_packets': 0,
                'uploaded_queries': 0,
                'packets_per_second': 0.0
            }
        
        try:
            stats = self.cpp_monitor.get_statistics()
            return {
                'total_packets': stats.total_packets,
                'dns_packets': stats.dns_packets,
                'uploaded_queries': stats.uploaded_queries,
                'packets_per_second': stats.packets_per_second
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}
    
    def update_config(self, new_config: Dict):
        """Update configuration and restart if necessary"""
        self.config.update(new_config)
        
        # Save updated config
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving config: {e}")
        
        # If monitor is running, update C++ config
        if self.cpp_monitor:
            try:
                cpp_config = dns_monitor_cpp.DeviceConfig()
                cpp_config.device_id = self.config['device_id']
                cpp_config.api_url = self.config['api_url']
                cpp_config.api_token = self.config.get('api_token', '')
                cpp_config.monitor_interface = self.config['monitor_interface']
                cpp_config.log_level = self.config.get('log_level', 'INFO')
                cpp_config.threat_threshold = self.config.get('threat_threshold', 0.7)
                cpp_config.upload_batch_size = self.config.get('upload_batch_size', 100)
                cpp_config.upload_interval_seconds = self.config.get('upload_interval_seconds', 30)
                
                self.cpp_monitor.update_config(cpp_config)
                logger.info("Configuration updated")
                
            except Exception as e:
                logger.error(f"Error updating C++ config: {e}")
    
    async def run_forever(self):
        """Run the monitor forever with periodic statistics reporting"""
        try:
            self.start()
            
            while self.is_running:
                await asyncio.sleep(300)  # Report every 5 minutes
                
                stats = self.get_statistics()
                logger.info(f"Statistics: {stats}")
                
        except KeyboardInterrupt:
            logger.info("Received interrupt signal")
        except Exception as e:
            logger.error(f"Error in main loop: {e}")
        finally:
            self.stop()

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='High-performance DNS monitoring device')
    parser.add_argument('--config', default='device/config.json', help='Config file path')
    parser.add_argument('--interface', help='Network interface to monitor')
    args = parser.parse_args()
    
    try:
        device = DNSFirewallDevice(args.config)
        
        # Override interface if specified
        if args.interface:
            device.config['monitor_interface'] = args.interface
        
        logger.info(f"Starting DNS Firewall Device: {device.config['device_id']}")
        logger.info(f"Using C++ engine for high-performance packet capture")
        
        # Run the device
        asyncio.run(device.run_forever())
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
