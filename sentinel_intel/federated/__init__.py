"""
Federated Learning Module for Sentinel Intel
Privacy-preserving threat intelligence sharing
"""

from .federated_trainer import FederatedTrainer, FederatedClient
from .privacy_engine import PrivacyEngine, SecureAggregator

__all__ = ['FederatedTrainer', 'FederatedClient', 'PrivacyEngine', 'SecureAggregator']
