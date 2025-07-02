#!/usr/bin/env python3
"""
Device-side DNS monitoring script for AI Privacy Firewall.
This script runs on the embedded device and monitors DNS traffic.
"""

import asyncio
import json
import time
import socket
import struct
import logging
from datetime import datetime
from typing import Dict, List
import aiohttp
import psutil
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DNSFirewallDevice:
    """Main device class for DNS monitoring and filtering"""
    
    def __init__(self, config_path: str = "/etc/dns-firewall/config.json"):
        self.config = self.load_config(config_path)
        self.device_id = self.config['device_id']
        self.api_url = self.config['api_url']
        self.api_token = self.config.get('api_token')
        
        # Network settings
        self.blocked_domains = set()
        self.allowed_domains = set()
        self.threat_threshold = 0.7
        
        # Statistics
        self.stats = {
            'total_queries': 0,
            'blocked_queries': 0,
            'allowed_queries': 0,
            'threats_detected': 0
        }
        
        # Load initial blocklist
        asyncio.create_task(self.load_network_settings())
    
    def load_config(self, config_path: str) -> Dict:
        """Load device configuration"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Get default configuration"""
        return {
            'device_id': self.get_device_id(),
            'api_url': 'http://localhost:8000/api',
            'monitor_interface': 'eth0',
            'dns_port': 53,
            'log_level': 'INFO'
        }
    
    def get_device_id(self) -> str:
        """Generate unique device ID based on MAC address"""
        try:
            # Get MAC address of the first network interface
            interfaces = psutil.net_if_addrs()
            for interface_name, interface_addresses in interfaces.items():
                for address in interface_addresses:
                    if address.family == psutil.AF_LINK:
                        return f"device_{address.address.replace(':', '')}"
        except Exception:
            pass
        
        # Fallback to hostname
        return f"device_{socket.gethostname()}"
    
    async def load_network_settings(self):
        """Load network settings from the backend API"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {'Authorization': f'Bearer {self.api_token}'} if self.api_token else {}
                
                async with session.get(
                    f"{self.api_url}/dns/devices/{self.device_id}/settings",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        settings = await response.json()
                        self.threat_threshold = settings.get('ai_threat_threshold', 0.7)
                        logger.info(f"Loaded network settings: threshold={self.threat_threshold}")
                    else:
                        logger.warning(f"Failed to load network settings: {response.status}")
        except Exception as e:
            logger.error(f"Error loading network settings: {e}")
    
    async def register_device(self):
        """Register this device with the backend"""
        device_info = {
            'device_id': self.device_id,
            'name': socket.gethostname(),
            'ip_address': self.get_local_ip(),
            'mac_address': self.get_mac_address(),
            'location': self.config.get('location', 'Unknown')
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/dns/devices",
                    json=device_info
                ) as response:
                    if response.status == 200:
                        logger.info("Device registered successfully")
                    else:
                        logger.warning(f"Device registration failed: {response.status}")
        except Exception as e:
            logger.error(f"Error registering device: {e}")
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            # Connect to a remote address to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def get_mac_address(self) -> str:
        """Get MAC address of primary network interface"""
        try:
            interfaces = psutil.net_if_addrs()
            for interface_name, interface_addresses in interfaces.items():
                if interface_name.startswith(('eth', 'wlan', 'en')):
                    for address in interface_addresses:
                        if address.family == psutil.AF_LINK:
                            return address.address
        except Exception:
            pass
        return "00:00:00:00:00:00"
    
    def packet_handler(self, packet):
        """Handle captured DNS packets"""
        try:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                # Extract DNS query information
                dns_query = {
                    'device_id': self.device_id,
                    'query_name': packet[DNSQR].qname.decode('utf-8').rstrip('.'),
                    'query_type': self.get_query_type(packet[DNSQR].qtype),
                    'client_ip': packet[IP].src,
                    'response_code': None,
                    'response_ip': None
                }
                
                # If this is a response, extract response information
                if packet[DNS].qr == 1 and packet.haslayer(DNSRR):
                    dns_query['response_code'] = self.get_response_code(packet[DNS].rcode)
                    if packet[DNSRR].rdata:
                        dns_query['response_ip'] = str(packet[DNSRR].rdata)
                
                # Process the query
                asyncio.create_task(self.process_dns_query(dns_query))
                
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def get_query_type(self, qtype: int) -> str:
        """Convert DNS query type number to string"""
        types = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA'}
        return types.get(qtype, str(qtype))
    
    def get_response_code(self, rcode: int) -> str:
        """Convert DNS response code to string"""
        codes = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
        return codes.get(rcode, str(rcode))
    
    async def process_dns_query(self, query_data: Dict):
        """Process a DNS query and apply filtering"""
        domain = query_data['query_name'].lower()
        
        # Update statistics
        self.stats['total_queries'] += 1
        
        # Check against local blocklist first
        if domain in self.blocked_domains:
            self.stats['blocked_queries'] += 1
            logger.info(f"Blocked domain from local list: {domain}")
            return
        
        # Check against local allowlist
        if domain in self.allowed_domains:
            self.stats['allowed_queries'] += 1
            return
        
        # Send to backend for AI analysis
        await self.analyze_with_backend(query_data)
    
    async def analyze_with_backend(self, query_data: Dict):
        """Send DNS query to backend for AI analysis"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_url}/dns/dns-queries",
                    json=query_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        
                        # Check if query was blocked
                        if result.get('status') == 'blocked':
                            self.stats['blocked_queries'] += 1
                            logger.info(f"Backend blocked domain: {query_data['query_name']}")
                            
                            # Add to local blocklist for faster future lookups
                            self.blocked_domains.add(query_data['query_name'].lower())
                        else:
                            self.stats['allowed_queries'] += 1
                            
                            # Add to local allowlist if safe
                            if result.get('threat_score', 1.0) < 0.1:
                                self.allowed_domains.add(query_data['query_name'].lower())
                    
                    else:
                        logger.warning(f"Backend analysis failed: {response.status}")
                        self.stats['allowed_queries'] += 1
                        
        except Exception as e:
            logger.error(f"Error analyzing with backend: {e}")
            # Default to allowing if backend is unavailable
            self.stats['allowed_queries'] += 1
    
    def start_monitoring(self):
        """Start DNS traffic monitoring"""
        interface = self.config.get('monitor_interface', 'eth0')
        
        logger.info(f"Starting DNS monitoring on interface: {interface}")
        
        try:
            # Start packet capture
            sniff(
                iface=interface,
                filter="udp port 53",
                prn=self.packet_handler,
                store=0
            )
        except Exception as e:
            logger.error(f"Error starting packet capture: {e}")
    
    async def report_statistics(self):
        """Periodically report statistics to backend"""
        while True:
            try:
                await asyncio.sleep(300)  # Report every 5 minutes
                
                logger.info(f"Statistics: {self.stats}")
                
                # Reset counters (optional, depending on requirements)
                # self.stats = {key: 0 for key in self.stats}
                
            except Exception as e:
                logger.error(f"Error reporting statistics: {e}")
    
    async def start_async_tasks(self):
        """Start async background tasks"""
        await self.register_device()
        await self.load_network_settings()
        
        # Start background tasks
        asyncio.create_task(self.report_statistics())
        
        # Start DNS monitoring in a separate thread (since scapy is blocking)
        import threading
        monitor_thread = threading.Thread(target=self.start_monitoring)
        monitor_thread.daemon = True
        monitor_thread.start()

def main():
    """Main entry point"""
    device = DNSFirewallDevice()
    
    logger.info(f"Starting DNS Firewall Device: {device.device_id}")
    
    # Start async event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(device.start_async_tasks())
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down DNS Firewall Device")
    finally:
        loop.close()

if __name__ == "__main__":
    main()
