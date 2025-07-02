"""
AI Services Module

Contains high-level AI services for threat detection and analysis.
"""

from .threat_detector import (
    ThreatDetectionService, 
    DNSThreatAnalyzer, 
    ThreatLevel, 
    ThreatType, 
    DNSQueryStatus,
    threat_detection_service
)

__all__ = [
    "ThreatDetectionService",
    "DNSThreatAnalyzer", 
    "ThreatLevel",
    "ThreatType",
    "DNSQueryStatus",
    "threat_detection_service"
]
