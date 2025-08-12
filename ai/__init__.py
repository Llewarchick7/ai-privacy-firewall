"""
AI Module for DNS Threat Detection and Analysis

This module contains all AI/ML components for the DNS firewall system:
- Machine learning models for threat detection
- Feature extraction and preprocessing
- Threat analysis services
- Model training and evaluation utilities
"""

__version__ = "1.0.0"
__author__ = "AI Privacy Firewall Team"

from .services.threat_detector import ThreatDetectionService
from .models.dns_classifier import DNSThreatClassifier
from .utils.feature_extractor import DomainFeatureExtractor

__all__ = [
    "ThreatDetectionService",
    "DNSThreatClassifier", 
    "DomainFeatureExtractor"
]
