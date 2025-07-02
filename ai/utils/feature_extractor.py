"""
Feature extraction utilities for DNS domain analysis.
Extracts both manual engineered features and TF-IDF features from domain names.
"""

import re
import numpy as np
from typing import List
from sklearn.feature_extraction.text import TfidfVectorizer


class DomainFeatureExtractor:
    """Extract features from domain names for ML models"""
    
    def __init__(self):
        self.tfidf = TfidfVectorizer(
            analyzer='char',
            ngram_range=(2, 4),
            max_features=1000,
            lowercase=True
        )
        self.fitted = False
    
    def extract_manual_features(self, domain: str) -> List[float]:
        """Extract manual engineered features from domain"""
        features = []
        
        # Length features
        features.append(len(domain))
        features.append(len(domain.split('.')))  # Number of subdomains
        
        # Character features
        features.append(domain.count('-'))  # Hyphens
        features.append(domain.count('_'))  # Underscores
        features.append(sum(c.isdigit() for c in domain))  # Digits
        features.append(sum(c.isupper() for c in domain))  # Uppercase letters
        
        # Entropy (randomness)
        features.append(self._calculate_entropy(domain))
        
        # Dictionary words ratio
        features.append(self._dictionary_words_ratio(domain))
        
        # Suspicious TLD
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
        features.append(int(any(domain.endswith(tld) for tld in suspicious_tlds)))
        
        # Length of longest subdomain
        subdomains = domain.split('.')[:-2]  # Exclude domain and TLD
        max_subdomain_length = max([len(sub) for sub in subdomains]) if subdomains else 0
        features.append(max_subdomain_length)
        
        return features
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        prob = [text.count(c) / len(text) for c in set(text)]
        entropy = -sum(p * np.log2(p) for p in prob if p > 0)
        return entropy
    
    def _dictionary_words_ratio(self, domain: str) -> float:
        """Calculate ratio of dictionary words in domain"""
        # Simple dictionary check (in production, use a proper dictionary)
        common_words = [
            'mail', 'www', 'web', 'secure', 'login', 'account', 'admin',
            'support', 'help', 'info', 'news', 'blog', 'shop', 'store'
        ]
        
        domain_lower = domain.lower()
        word_count = sum(1 for word in common_words if word in domain_lower)
        return word_count / len(common_words)
    
    def fit_transform(self, domains: List[str]) -> np.ndarray:
        """Fit TF-IDF and extract all features"""
        # Fit TF-IDF
        tfidf_features = self.tfidf.fit_transform(domains)
        self.fitted = True
        
        # Extract manual features
        manual_features = np.array([
            self.extract_manual_features(domain) for domain in domains
        ])
        
        # Combine features
        combined_features = np.hstack([
            tfidf_features.toarray(),
            manual_features
        ])
        
        return combined_features
    
    def transform(self, domains: List[str]) -> np.ndarray:
        """Transform domains to features (after fitting)"""
        if not self.fitted:
            raise ValueError("Feature extractor must be fitted first")
        
        # Transform with TF-IDF
        tfidf_features = self.tfidf.transform(domains)
        
        # Extract manual features
        manual_features = np.array([
            self.extract_manual_features(domain) for domain in domains
        ])
        
        # Combine features
        combined_features = np.hstack([
            tfidf_features.toarray(),
            manual_features
        ])
        
        return combined_features
