"""
Main threat detection service that orchestrates various AI analysis methods.
Combines multiple detection techniques for comprehensive DNS threat analysis.
"""

import re
import json
import requests
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from enum import Enum

from ..models.dns_classifier import DNSThreatClassifier


class ThreatLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(str, Enum):
    MALWARE = "malware"
    PHISHING = "phishing"
    DATA_EXFILTRATION = "data_exfiltration"
    DNS_TUNNELING = "dns_tunneling"
    BOTNET = "botnet"
    SUSPICIOUS_DOMAIN = "suspicious_domain"


class DNSQueryStatus(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    FLAGGED = "flagged"


class DNSThreatAnalyzer:
    """Main class for DNS threat analysis using multiple detection methods"""
    
    def __init__(self):
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download', '.stream',
            '.party', '.trade', '.bid', '.science', '.date', '.racing'
        ]
        
        self.malware_keywords = [
            'malware', 'virus', 'trojan', 'backdoor', 'keylogger', 'spyware',
            'ransomware', 'exploit', 'payload', 'shell', 'botnet', 'c2', 'cnc'
        ]
        
        self.phishing_keywords = [
            'secure', 'verify', 'update', 'confirm', 'account', 'login',
            'bank', 'paypal', 'amazon', 'microsoft', 'apple', 'google'
        ]
        
        # Initialize ML model (will be loaded when needed)
        self.ml_model = None
        
    def analyze_dns_query(self, query_name: str, query_type: str, client_ip: str) -> Dict:
        """
        Main analysis function that combines multiple detection methods
        
        Args:
            query_name: Domain name being queried
            query_type: DNS query type (A, AAAA, etc.)
            client_ip: IP address making the request
            
        Returns:
            Dict with analysis results
        """
        domain = query_name.lower()
        
        # Initialize analysis result
        analysis = {
            'domain': domain,
            'threat_score': 0.0,
            'is_malicious': False,
            'threat_types': [],
            'confidence': 0.0,
            'detection_methods': [],
            'recommended_action': 'allow'
        }
        
        # 1. Domain reputation check (placeholder - would integrate with external APIs)
        reputation_score = self._check_domain_reputation(domain)
        if reputation_score:
            analysis['threat_score'] = max(analysis['threat_score'], 1.0 - reputation_score)
            analysis['detection_methods'].append('reputation')
        
        # 2. Heuristic analysis
        heuristic_score, heuristic_threats = self._heuristic_analysis(domain)
        analysis['threat_score'] = max(analysis['threat_score'], heuristic_score)
        analysis['threat_types'].extend(heuristic_threats)
        if heuristic_score > 0.3:
            analysis['detection_methods'].append('heuristic')
        
        # 3. DNS tunneling detection
        tunneling_score = self._detect_dns_tunneling(query_name, query_type)
        if tunneling_score > 0.5:
            analysis['threat_score'] = max(analysis['threat_score'], tunneling_score)
            analysis['threat_types'].append(ThreatType.DNS_TUNNELING)
            analysis['detection_methods'].append('dns_tunneling')
        
        # 4. Domain generation algorithm (DGA) detection
        dga_score = self._detect_dga(domain)
        if dga_score > 0.6:
            analysis['threat_score'] = max(analysis['threat_score'], dga_score)
            analysis['threat_types'].append(ThreatType.BOTNET)
            analysis['detection_methods'].append('dga')
        
        # 5. ML-based classification
        if self.ml_model:
            try:
                ml_results = self.ml_model.predict([domain])
                if ml_results:
                    ml_score = ml_results[0]['threat_score']
                    analysis['threat_score'] = max(analysis['threat_score'], ml_score)
                    analysis['detection_methods'].append('ml_classifier')
            except Exception as e:
                print(f"ML model prediction failed: {e}")
        
        # Determine final classification
        analysis['is_malicious'] = analysis['threat_score'] > 0.7
        analysis['confidence'] = min(analysis['threat_score'] * 1.2, 1.0)
        
        # Recommend action
        if analysis['threat_score'] > 0.8:
            analysis['recommended_action'] = 'block'
        elif analysis['threat_score'] > 0.5:
            analysis['recommended_action'] = 'flag'
        else:
            analysis['recommended_action'] = 'allow'
        
        return analysis
    
    def _check_domain_reputation(self, domain: str) -> Optional[float]:
        """Check domain reputation from external sources"""
        # This would integrate with actual threat intelligence APIs
        # For now, return a basic check
        
        # Simple blacklist check (would be replaced with real API calls)
        known_malicious = [
            'malware.com', 'phishing.net', 'badactor.org'
        ]
        
        if domain in known_malicious:
            return 0.1  # Low reputation score
        
        return 0.8  # Default safe score
    
    def _heuristic_analysis(self, domain: str) -> Tuple[float, List[str]]:
        """Heuristic analysis based on domain characteristics"""
        score = 0.0
        threat_types = []
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                score += 0.3
                threat_types.append(ThreatType.SUSPICIOUS_DOMAIN)
                break
        
        # Check for malware keywords
        for keyword in self.malware_keywords:
            if keyword in domain:
                score += 0.4
                threat_types.append(ThreatType.MALWARE)
                break
        
        # Check for phishing keywords
        for keyword in self.phishing_keywords:
            if keyword in domain:
                score += 0.3
                threat_types.append(ThreatType.PHISHING)
                break
        
        # Check domain length and complexity
        if len(domain) > 50:
            score += 0.2
        
        # Check for excessive subdomains
        subdomain_count = domain.count('.')
        if subdomain_count > 4:
            score += 0.3
            threat_types.append(ThreatType.SUSPICIOUS_DOMAIN)
        
        # Check for homograph attacks (basic)
        suspicious_chars = ['xn--', '0', '1', 'l', 'o']
        if any(char in domain for char in suspicious_chars):
            score += 0.1
        
        return min(score, 1.0), threat_types
    
    def _detect_dns_tunneling(self, query_name: str, query_type: str) -> float:
        """Detect potential DNS tunneling based on query characteristics"""
        domain = query_name
        
        # Check for long subdomain names (common in DNS tunneling)
        subdomains = domain.split('.')[:-2]  # Exclude TLD and domain
        
        for subdomain in subdomains:
            if len(subdomain) > 63:  # DNS label limit
                return 0.9
            if len(subdomain) > 30:  # Suspicious length
                return 0.7
        
        # Check for base64-like patterns
        base64_pattern = re.compile(r'^[A-Za-z0-9+/=]+$')
        for subdomain in subdomains:
            if len(subdomain) > 10 and base64_pattern.match(subdomain):
                return 0.8
        
        # Check for high entropy (randomness)
        for subdomain in subdomains:
            if len(subdomain) > 8:
                entropy = self._calculate_entropy(subdomain)
                if entropy > 4.5:  # High entropy indicates randomness
                    return 0.6
        
        # Check for unusual query types used in tunneling
        tunneling_types = ['TXT', 'CNAME', 'MX', 'NULL']
        if query_type in tunneling_types and len(domain) > 30:
            return 0.5
        
        return 0.0
    
    def _detect_dga(self, domain: str) -> float:
        """Detect Domain Generation Algorithm (DGA) generated domains"""
        # Extract the main domain (without subdomains)
        parts = domain.split('.')
        if len(parts) < 2:
            return 0.0
        
        main_domain = parts[-2]  # Domain name without TLD
        
        # Check length
        if len(main_domain) < 6 or len(main_domain) > 20:
            return 0.3
        
        # Calculate entropy
        entropy = self._calculate_entropy(main_domain)
        if entropy > 4.0:
            return 0.7
        
        # Check for consonant/vowel ratio
        vowels = 'aeiou'
        vowel_count = sum(1 for char in main_domain if char in vowels)
        consonant_count = len(main_domain) - vowel_count
        
        if vowel_count == 0 or consonant_count / vowel_count > 5:
            return 0.6
        
        # Check for repeated patterns
        if len(set(main_domain)) < len(main_domain) * 0.5:
            return 0.4
        
        return 0.0
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p = text.count(char) / len(text)
            if p > 0:
                entropy -= p * (p ** 0.5).bit_length()
        
        return entropy
    
    def load_ml_model(self, model_path: str):
        """Load the ML model for enhanced detection"""
        try:
            self.ml_model = DNSThreatClassifier()
            self.ml_model.load_model(model_path)
            print("ML model loaded successfully")
        except Exception as e:
            print(f"Failed to load ML model: {e}")
            self.ml_model = None


class ThreatDetectionService:
    """Service for creating and managing threat detections"""
    
    def __init__(self, model_path: str = None):
        self.analyzer = DNSThreatAnalyzer()
        
        # Load ML model if path provided
        if model_path:
            self.analyzer.load_ml_model(model_path)
    
    def analyze_query(self, query_name: str, query_type: str, client_ip: str) -> Dict:
        """
        Analyze a DNS query for threats
        
        Args:
            query_name: Domain name being queried
            query_type: DNS query type
            client_ip: IP address making the request
            
        Returns:
            Analysis results with threat assessment
        """
        return self.analyzer.analyze_dns_query(query_name, query_type, client_ip)
    
    def determine_threat_level(self, threat_score: float) -> ThreatLevel:
        """Determine threat level based on threat score"""
        if threat_score >= 0.9:
            return ThreatLevel.CRITICAL
        elif threat_score >= 0.7:
            return ThreatLevel.HIGH
        elif threat_score >= 0.5:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW
    
    def determine_status(self, recommended_action: str) -> DNSQueryStatus:
        """Determine DNS query status based on recommendation"""
        action_map = {
            'block': DNSQueryStatus.BLOCKED,
            'flag': DNSQueryStatus.FLAGGED,
            'allow': DNSQueryStatus.ALLOWED
        }
        return action_map.get(recommended_action, DNSQueryStatus.ALLOWED)


# Global service instance
threat_detection_service = ThreatDetectionService()
