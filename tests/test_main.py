"""
Simple test version of the AI Privacy Firewall API for basic testing.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List
import json
from datetime import datetime

# Initialize FastAPI app
app = FastAPI(
    title="AI Privacy Firewall API - Test Version",
    description="AI-powered DNS firewall for network threat detection and privacy protection",
    version="1.0.0"
)

# Simple data models for testing
class DNSQuery(BaseModel):
    device_id: str
    query_name: str
    query_type: str = "A"
    client_ip: str
    timestamp: str = None

class ThreatDetection(BaseModel):
    query_name: str
    threat_score: float
    threat_type: str
    blocked: bool

class DeviceInfo(BaseModel):
    device_id: str
    name: str
    ip_address: str
    mac_address: str
    location: str = "Unknown"

# In-memory storage for testing (replace with database in production)
devices: Dict[str, DeviceInfo] = {}
dns_queries: List[DNSQuery] = []
threats: List[ThreatDetection] = []

@app.get("/")
async def read_root():
    """Root endpoint - health check"""
    return {
        "message": "AI Privacy Firewall API is running!",
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "services": {
            "api": "running",
            "database": "simulated",
            "ai_engine": "simulated"
        },
        "stats": {
            "devices": len(devices),
            "dns_queries": len(dns_queries),
            "threats": len(threats)
        }
    }

# Device Management Endpoints
@app.post("/api/dns/devices", tags=["Device Management"])
async def register_device(device: DeviceInfo):
    """Register a new firewall device"""
    if device.device_id in devices:
        raise HTTPException(status_code=400, detail="Device already registered")
    
    devices[device.device_id] = device
    return {
        "message": "Device registered successfully",
        "device_id": device.device_id,
        "status": "active"
    }

@app.get("/api/dns/devices", tags=["Device Management"])
async def list_devices():
    """List all registered devices"""
    return {
        "devices": list(devices.values()),
        "total": len(devices)
    }

@app.get("/api/dns/devices/{device_id}", tags=["Device Management"])
async def get_device(device_id: str):
    """Get specific device information"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail="Device not found")
    
    return devices[device_id]

# DNS Monitoring Endpoints
@app.post("/api/dns/dns-queries", tags=["DNS Monitoring"])
async def log_dns_query(query: DNSQuery):
    """Log a DNS query from a device"""
    if not query.timestamp:
        query.timestamp = datetime.now().isoformat()
    
    # Simulate AI threat detection
    threat_score = simulate_threat_detection(query.query_name)
    
    dns_queries.append(query)
    
    # If threat score is high, log as threat
    if threat_score > 0.7:
        threat = ThreatDetection(
            query_name=query.query_name,
            threat_score=threat_score,
            threat_type="suspicious_domain",
            blocked=True
        )
        threats.append(threat)
        
        return {
            "status": "blocked",
            "reason": "High threat score",
            "threat_score": threat_score,
            "query_id": len(dns_queries)
        }
    
    return {
        "status": "allowed",
        "threat_score": threat_score,
        "query_id": len(dns_queries)
    }

@app.get("/api/dns/queries", tags=["DNS Monitoring"])
async def get_dns_queries(limit: int = 100):
    """Get recent DNS queries"""
    return {
        "queries": dns_queries[-limit:],
        "total": len(dns_queries)
    }

@app.get("/api/dns/threats", tags=["DNS Monitoring"])
async def get_threats(limit: int = 50):
    """Get detected threats"""
    return {
        "threats": threats[-limit:],
        "total": len(threats)
    }

# Analytics Endpoints
@app.get("/api/dns/analytics/network", tags=["Analytics"])
async def get_network_analytics():
    """Get network analytics summary"""
    total_queries = len(dns_queries)
    total_threats = len(threats)
    
    return {
        "summary": {
            "total_devices": len(devices),
            "total_queries": total_queries,
            "total_threats": total_threats,
            "threat_percentage": (total_threats / total_queries * 100) if total_queries > 0 else 0
        },
        "recent_activity": dns_queries[-10:] if dns_queries else []
    }

@app.get("/api/dns/analytics/device/{device_id}", tags=["Analytics"])
async def get_device_analytics(device_id: str):
    """Get analytics for a specific device"""
    if device_id not in devices:
        raise HTTPException(status_code=404, detail="Device not found")
    
    device_queries = [q for q in dns_queries if q.device_id == device_id]
    device_threats = [t for t in threats if any(q.query_name == t.query_name and q.device_id == device_id for q in dns_queries)]
    
    return {
        "device_id": device_id,
        "queries": len(device_queries),
        "threats": len(device_threats),
        "recent_queries": device_queries[-10:] if device_queries else []
    }

# Utility Functions
def simulate_threat_detection(domain: str) -> float:
    """Simulate AI threat detection - returns threat score 0-1"""
    suspicious_indicators = [
        '.tk', '.ml', '.ga', '.cf',  # Suspicious TLDs
        'phishing', 'malware', 'spam', 'scam',  # Suspicious keywords
        'bit.ly', 'tinyurl'  # URL shorteners
    ]
    
    domain_lower = domain.lower()
    threat_score = 0.0
    
    # Check for suspicious indicators
    for indicator in suspicious_indicators:
        if indicator in domain_lower:
            threat_score += 0.3
    
    # Check for domain length (very long domains are suspicious)
    if len(domain) > 50:
        threat_score += 0.2
    
    # Check for excessive subdomains
    if domain.count('.') > 4:
        threat_score += 0.2
    
    # Random elements for testing
    import random
    threat_score += random.uniform(0, 0.3)
    
    return min(threat_score, 1.0)

# Test data for demonstration
@app.post("/api/test/populate", tags=["Testing"])
async def populate_test_data():
    """Populate with test data for demonstration"""
    # Add test devices
    test_devices = [
        DeviceInfo(device_id="device_001", name="Home Router", ip_address="192.168.1.1", mac_address="aa:bb:cc:dd:ee:01", location="Living Room"),
        DeviceInfo(device_id="device_002", name="Office Firewall", ip_address="10.0.1.1", mac_address="aa:bb:cc:dd:ee:02", location="Server Room"),
    ]
    
    for device in test_devices:
        devices[device.device_id] = device
    
    # Add test DNS queries
    test_queries = [
        DNSQuery(device_id="device_001", query_name="google.com", query_type="A", client_ip="192.168.1.100"),
        DNSQuery(device_id="device_001", query_name="suspicious-domain.tk", query_type="A", client_ip="192.168.1.101"),
        DNSQuery(device_id="device_002", query_name="github.com", query_type="A", client_ip="10.0.1.50"),
        DNSQuery(device_id="device_002", query_name="malware-site.ml", query_type="A", client_ip="10.0.1.51"),
    ]
    
    for query in test_queries:
        query.timestamp = datetime.now().isoformat()
        threat_score = simulate_threat_detection(query.query_name)
        dns_queries.append(query)
        
        if threat_score > 0.7:
            threat = ThreatDetection(
                query_name=query.query_name,
                threat_score=threat_score,
                threat_type="test_threat",
                blocked=True
            )
            threats.append(threat)
    
    return {
        "message": "Test data populated successfully",
        "devices_added": len(test_devices),
        "queries_added": len(test_queries),
        "threats_detected": len([t for t in threats if t.threat_type == "test_threat"])
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
