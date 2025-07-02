"""
AI Models Module

Contains machine learning models for threat detection.
"""

from .dns_classifier import DNSThreatClassifier, create_sample_training_data, train_model

__all__ = ["DNSThreatClassifier", "create_sample_training_data", "train_model"]
