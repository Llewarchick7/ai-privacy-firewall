"""
DNS monitoring models for the AI Privacy Firewall.
Handles DNS queries, threat detections, and device management.
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Float, Text, ForeignKey, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from backend.database import Base
import enum

class ThreatLevel(enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DNSQueryStatus(enum.Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"

class Device(Base):
    """Represents a physical firewall device on the network"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(String, unique=True, nullable=False, index=True)  # Hardware MAC or UUID
    name = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    mac_address = Column(String, unique=True, nullable=False)
    location = Column(String, nullable=True)  # Physical location
    is_active = Column(Boolean, default=True)
    last_seen = Column(DateTime, default=func.now())
    firmware_version = Column(String, nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    # Provisioning / enrollment
    status = Column(String, default="active")  # pending, active, disabled
    device_secret = Column(String, nullable=True, index=True)  # per-device ingest secret (hex/random)
    enrollment_code = Column(String, nullable=True, index=True)  # short one-time code for setup
    enrollment_expires_at = Column(DateTime, nullable=True)
    device_type = Column(String, default="collector")  # collector, legacy
    # Relationships
    user = relationship("Users", back_populates="devices")
    dns_queries = relationship("DNSQuery", back_populates="device", cascade="all, delete-orphan")
    threat_detections = relationship("ThreatDetection", back_populates="device", cascade="all, delete-orphan")

class Collector(Base):
    """Physical ingestion appliance (e.g., Raspberry Pi) providing DNS data for multiple endpoints."""
    __tablename__ = "collectors"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String, nullable=False)
    uuid = Column(String, unique=True, nullable=False, index=True)
    secret = Column(String, nullable=False)
    status = Column(String, default="active")
    last_seen = Column(DateTime, default=func.now())

class Endpoint(Base):
    """Network endpoint (client device) observed via a collector."""
    __tablename__ = "endpoints"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    collector_id = Column(Integer, ForeignKey("collectors.id"), nullable=True)
    mac_address = Column(String, index=True, nullable=False)
    ip_address = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    friendly_name = Column(String, nullable=True)
    first_seen = Column(DateTime, default=func.now())
    last_seen = Column(DateTime, default=func.now())
    status = Column(String, default="observed")  # observed, labeled, ignored

class RefreshSession(Base):
    """Refresh token sessions for long-lived authentication."""
    __tablename__ = "refresh_sessions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, index=True, nullable=False)
    issued_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    user_agent = Column(String, nullable=True)
    ip_address = Column(String, nullable=True)
    revoked = Column(Boolean, default=False)
    
    # Relationships
    user = relationship("Users", back_populates="refresh_sessions")

class DNSQuery(Base):
    """Individual DNS query logs from devices"""
    __tablename__ = "dns_queries"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    timestamp = Column(DateTime, default=func.now(), index=True)
    
    # DNS Query Details
    query_name = Column(String, nullable=False, index=True)  # The domain being queried
    query_type = Column(String, nullable=False)  # A, AAAA, MX, etc.
    client_ip = Column(String, nullable=False)  # Device making the request
    response_code = Column(String, nullable=True)  # NOERROR, NXDOMAIN, etc.
    response_ip = Column(String, nullable=True)  # Resolved IP address
    
    # Analysis Results
    status = Column(Enum(DNSQueryStatus), default=DNSQueryStatus.ALLOWED)
    threat_score = Column(Float, default=0.0)  # AI-generated threat score 0-1
    is_malicious = Column(Boolean, default=False)
    blocked_reason = Column(String, nullable=True)
    endpoint_id = Column(Integer, ForeignKey("endpoints.id"), nullable=True, index=True)
    
    # Relationships
    device = relationship("Device", back_populates="dns_queries")
    threat_detections = relationship("ThreatDetection", back_populates="dns_query")

class ThreatDetection(Base):
    """AI-detected threats and anomalies"""
    __tablename__ = "threat_detections"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    dns_query_id = Column(Integer, ForeignKey("dns_queries.id"), nullable=True)
    timestamp = Column(DateTime, default=func.now(), index=True)
    
    # Threat Details
    threat_type = Column(String, nullable=False)  # malware, phishing, data_exfiltration, etc.
    threat_level = Column(Enum(ThreatLevel), nullable=False)
    confidence_score = Column(Float, nullable=False)  # AI confidence 0-1
    
    # Detection Details
    detected_by = Column(String, nullable=False)  # ai_model, blacklist, heuristic, etc.
    model_version = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    indicators = Column(Text, nullable=True)  # JSON array of IOCs
    
    # Response
    is_blocked = Column(Boolean, default=False)
    action_taken = Column(String, nullable=True)  # block, alert, quarantine
    is_false_positive = Column(Boolean, default=False)
    
    # Relationships
    device = relationship("Device", back_populates="threat_detections")
    dns_query = relationship("DNSQuery", back_populates="threat_detections")

class DomainReputation(Base):
    """Domain reputation and classification cache"""
    __tablename__ = "domain_reputation"
    
    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, nullable=False, index=True)
    
    # Reputation Scores
    reputation_score = Column(Float, nullable=False)  # 0-1, higher is safer
    threat_categories = Column(String, nullable=True)  # JSON array
    last_updated = Column(DateTime, default=func.now())
    
    # External Sources
    virustotal_score = Column(Integer, nullable=True)
    safebrowsing_status = Column(String, nullable=True)
    alexa_rank = Column(Integer, nullable=True)
    
    # Classification
    is_malicious = Column(Boolean, default=False)
    is_suspicious = Column(Boolean, default=False)
    category = Column(String, nullable=True)  # social_media, cdn, ads, etc.

class NetworkSettings(Base):
    """Device-specific network and filtering settings"""
    __tablename__ = "network_settings"
    
    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), unique=True, nullable=False)
    
    # DNS Filtering Settings
    enable_malware_blocking = Column(Boolean, default=True)
    enable_phishing_blocking = Column(Boolean, default=True)
    enable_adult_content_blocking = Column(Boolean, default=False)
    enable_ads_blocking = Column(Boolean, default=False)
    enable_social_media_blocking = Column(Boolean, default=False)
    
    # AI Settings
    ai_threat_threshold = Column(Float, default=0.7)  # Block threshold
    enable_behavioral_analysis = Column(Boolean, default=True)
    enable_dns_tunneling_detection = Column(Boolean, default=True)
    
    # Logging Settings
    log_retention_days = Column(Integer, default=30)
    enable_detailed_logging = Column(Boolean, default=True)
    
    # Relationship
    device = relationship("Device", backref="network_settings")
