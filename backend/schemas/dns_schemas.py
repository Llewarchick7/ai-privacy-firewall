"""
Pydantic schemas for DNS monitoring and threat detection endpoints.
"""

from pydantic import BaseModel, IPvAnyAddress, validator
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class DNSQueryStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"

class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    BOTNET = "botnet"
    SUSPICIOUS_DOMAIN = "suspicious_domain"

# Device Schemas
class DeviceCreate(BaseModel):
    device_id: str
    name: str
    ip_address: str
    mac_address: str
    location: Optional[str] = None

class DeviceResponse(BaseModel):
    id: int
    device_id: str
    name: str
    ip_address: str
    mac_address: str
    location: Optional[str]
    is_active: bool
    last_seen: datetime
    firmware_version: Optional[str]
    
    class Config:
        from_attributes = True

class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    location: Optional[str] = None
    is_active: Optional[bool] = None

# DNS Query Schemas
class DNSQueryCreate(BaseModel):
    device_id: int
    query_name: str
    query_type: str
    client_ip: str
    response_code: Optional[str] = None
    response_ip: Optional[str] = None

class DNSQueryResponse(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    query_name: str
    query_type: str
    client_ip: str
    response_code: Optional[str]
    response_ip: Optional[str]
    status: DNSQueryStatus
    threat_score: float
    is_malicious: bool
    blocked_reason: Optional[str]
    
    class Config:
        from_attributes = True

class DNSQueryAnalysis(BaseModel):
    query_id: int
    threat_score: float
    is_malicious: bool
    threat_categories: List[str]
    confidence: float
    recommended_action: str

# Threat Detection Schemas
class ThreatDetectionCreate(BaseModel):
    device_id: int
    dns_query_id: Optional[int] = None
    threat_type: ThreatType
    threat_level: ThreatLevel
    confidence_score: float
    detected_by: str
    model_version: Optional[str] = None
    description: Optional[str] = None
    indicators: Optional[Dict[str, Any]] = None

class ThreatDetectionResponse(BaseModel):
    id: int
    device_id: int
    dns_query_id: Optional[int]
    timestamp: datetime
    threat_type: ThreatType
    threat_level: ThreatLevel
    confidence_score: float
    detected_by: str
    description: Optional[str]
    is_blocked: bool
    action_taken: Optional[str]
    is_false_positive: bool
    
    class Config:
        from_attributes = True

class ThreatSummary(BaseModel):
    total_threats: int
    critical_threats: int
    high_threats: int
    medium_threats: int
    low_threats: int
    blocked_queries: int
    top_threat_types: List[Dict[str, int]]

# Domain Reputation Schemas
class DomainReputationResponse(BaseModel):
    domain: str
    reputation_score: float
    threat_categories: Optional[List[str]]
    is_malicious: bool
    is_suspicious: bool
    category: Optional[str]
    last_updated: datetime
    
    class Config:
        from_attributes = True

class DomainAnalysisRequest(BaseModel):
    domain: str
    force_refresh: bool = False

# Network Settings Schemas
class NetworkSettingsUpdate(BaseModel):
    enable_malware_blocking: Optional[bool] = None
    enable_phishing_blocking: Optional[bool] = None
    enable_adult_content_blocking: Optional[bool] = None
    enable_ads_blocking: Optional[bool] = None
    enable_social_media_blocking: Optional[bool] = None
    ai_threat_threshold: Optional[float] = None
    enable_behavioral_analysis: Optional[bool] = None
    enable_dns_tunneling_detection: Optional[bool] = None
    log_retention_days: Optional[int] = None
    enable_detailed_logging: Optional[bool] = None
    
    @validator('ai_threat_threshold')
    def validate_threshold(cls, v):
        if v is not None and (v < 0 or v > 1):
            raise ValueError('AI threat threshold must be between 0 and 1')
        return v

class NetworkSettingsResponse(BaseModel):
    device_id: int
    enable_malware_blocking: bool
    enable_phishing_blocking: bool
    enable_adult_content_blocking: bool
    enable_ads_blocking: bool
    enable_social_media_blocking: bool
    ai_threat_threshold: float
    enable_behavioral_analysis: bool
    enable_dns_tunneling_detection: bool
    log_retention_days: int
    enable_detailed_logging: bool
    
    class Config:
        from_attributes = True

# Dashboard and Analytics Schemas
class DeviceStats(BaseModel):
    device_id: int
    device_name: str
    total_queries: int
    blocked_queries: int
    threat_detections: int
    last_activity: datetime

class NetworkAnalytics(BaseModel):
    total_devices: int
    active_devices: int
    total_queries_24h: int
    blocked_queries_24h: int
    threats_detected_24h: int
    top_blocked_domains: List[Dict[str, int]]
    threat_timeline: List[Dict[str, Any]]

class AlertCreate(BaseModel):
    device_id: int
    alert_type: str
    severity: ThreatLevel
    message: str
    details: Optional[Dict[str, Any]] = None

class AlertResponse(BaseModel):
    id: int
    device_id: int
    timestamp: datetime
    alert_type: str
    severity: ThreatLevel
    message: str
    is_acknowledged: bool
    
    class Config:
        from_attributes = True
