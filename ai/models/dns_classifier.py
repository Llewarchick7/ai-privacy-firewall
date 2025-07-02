"""
DNS Threat Classification Models

Contains machine learning models for classifying DNS domains as malicious or benign.
Uses Random Forest and Isolation Forest for classification and anomaly detection.
"""

import pickle
import numpy as np
import pandas as pd
from typing import List, Dict, Tuple
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import os

from ..utils.feature_extractor import DomainFeatureExtractor


class DNSThreatClassifier:
    """Main classifier for DNS threats"""
    
    def __init__(self):
        self.feature_extractor = DomainFeatureExtractor()
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            class_weight='balanced'
        )
        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self.trained = False
    
    def train(self, domains: List[str], labels: List[int], 
              save_path: str = "ai/models/dns_threat_classifier.pkl"):
        """Train the classifier"""
        
        # Extract features
        X = self.feature_extractor.fit_transform(domains)
        y = np.array(labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train classifier
        self.classifier.fit(X_train, y_train)
        
        # Train anomaly detector on benign samples only
        benign_X = X_train[y_train == 0]
        self.anomaly_detector.fit(benign_X)
        
        # Evaluate
        y_pred = self.classifier.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model accuracy: {accuracy:.3f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        self.trained = True
        
        # Save model
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        self.save_model(save_path)
        
        return accuracy
    
    def predict(self, domains: List[str]) -> List[Dict]:
        """Predict threats for domains"""
        if not self.trained:
            raise ValueError("Model must be trained first")
        
        # Extract features
        X = self.feature_extractor.transform(domains)
        
        # Get predictions
        predictions = self.classifier.predict(X)
        probabilities = self.classifier.predict_proba(X)
        anomaly_scores = self.anomaly_detector.decision_function(X)
        
        results = []
        for i, domain in enumerate(domains):
            malicious_prob = probabilities[i][1] if len(probabilities[i]) > 1 else 0.0
            
            # Combine classifier and anomaly detection
            final_score = malicious_prob * 0.8 + (1 - anomaly_scores[i]) * 0.2
            final_score = max(0.0, min(1.0, final_score))
            
            results.append({
                'domain': domain,
                'is_malicious': predictions[i] == 1,
                'threat_score': final_score,
                'malicious_probability': malicious_prob,
                'anomaly_score': anomaly_scores[i]
            })
        
        return results
    
    def save_model(self, path: str):
        """Save the trained model"""
        model_data = {
            'feature_extractor': self.feature_extractor,
            'classifier': self.classifier,
            'anomaly_detector': self.anomaly_detector,
            'trained': self.trained
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
    
    def load_model(self, path: str):
        """Load a trained model"""
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        self.feature_extractor = model_data['feature_extractor']
        self.classifier = model_data['classifier']
        self.anomaly_detector = model_data['anomaly_detector']
        self.trained = model_data['trained']


def create_sample_training_data() -> Tuple[List[str], List[int]]:
    """Create sample training data for demonstration"""
    
    # Malicious domains (label = 1)
    malicious_domains = [
        'xn--e1afmkfd.xn--p1ai',  # IDN homograph
        'goog1e.com',  # Typosquatting
        'paypa1.com',  # Typosquatting
        'microsft-security.tk',  # Suspicious TLD + typo
        'aHR0cDovL21hbHdhcmUuY29t.evil.com',  # Base64-like
        'randomstring123456789.ga',  # Random + suspicious TLD
        'xvfdbghnm.ml',  # Random characters
        'secure-update-required.click',  # Phishing keywords
        'win-prize-now.download',  # Suspicious keywords
        'urgent-action-needed.bid',  # Phishing pattern
    ]
    
    # Benign domains (label = 0)
    benign_domains = [
        'google.com',
        'facebook.com',
        'amazon.com',
        'microsoft.com',
        'apple.com',
        'github.com',
        'stackoverflow.com',
        'wikipedia.org',
        'youtube.com',
        'linkedin.com',
        'news.bbc.co.uk',
        'mail.google.com',
        'docs.microsoft.com',
        'support.apple.com',
        'help.github.com',
    ]
    
    domains = malicious_domains + benign_domains
    labels = [1] * len(malicious_domains) + [0] * len(benign_domains)
    
    return domains, labels


def train_model():
    """Train the DNS threat classification model"""
    
    # Create sample data
    domains, labels = create_sample_training_data()
    
    # Initialize and train classifier
    classifier = DNSThreatClassifier()
    accuracy = classifier.train(domains, labels)
    
    print(f"\nModel trained successfully with {accuracy:.1%} accuracy")
    
    # Test with some examples
    test_domains = [
        'google.com',
        'malware-site.tk',
        'xn--e1afmkfd.xn--p1ai',
        'legitimate-site.org'
    ]
    
    predictions = classifier.predict(test_domains)
    
    print("\nTest predictions:")
    for pred in predictions:
        print(f"{pred['domain']}: {pred['threat_score']:.3f} "
              f"({'MALICIOUS' if pred['is_malicious'] else 'BENIGN'})")


if __name__ == "__main__":
    train_model()
