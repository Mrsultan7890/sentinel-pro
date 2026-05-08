"""
Federated Learning Trainer
Train SentinelNet across multiple nodes without sharing raw data
"""

import torch
import torch.nn as nn
from typing import List, Dict, Any
import hashlib
import json
from pathlib import Path

class FederatedTrainer:
    """Federated learning coordinator for SentinelNet"""
    
    def __init__(self, model_path: str = "models/ml_engine/sentinel_threat_net.pt"):
        self.model_path = Path(model_path)
        self.global_model = None
        self.client_models: List[Dict] = []
        self.round_number = 0
        
    def initialize_global_model(self):
        """Load or create global model"""
        if self.model_path.exists():
            self.global_model = torch.load(self.model_path)
        else:
            raise FileNotFoundError(f"Model not found: {self.model_path}")
    
    def get_global_weights(self) -> Dict[str, torch.Tensor]:
        """Get current global model weights"""
        if self.global_model is None:
            self.initialize_global_model()
        return self.global_model.state_dict()
    
    def aggregate_weights(self, client_weights: List[Dict[str, torch.Tensor]], 
                         client_sizes: List[int]) -> Dict[str, torch.Tensor]:
        """
        Federated averaging (FedAvg)
        Weighted average based on client dataset sizes
        """
        total_size = sum(client_sizes)
        aggregated = {}
        
        # Get all parameter names from first client
        param_names = client_weights[0].keys()
        
        for param_name in param_names:
            # Weighted sum
            weighted_sum = sum(
                weights[param_name] * (size / total_size)
                for weights, size in zip(client_weights, client_sizes)
            )
            aggregated[param_name] = weighted_sum
        
        return aggregated
    
    def update_global_model(self, client_updates: List[Dict[str, Any]]):
        """
        Update global model with client updates
        
        client_updates format:
        [
            {
                'weights': state_dict,
                'dataset_size': int,
                'client_id': str,
                'accuracy': float
            },
            ...
        ]
        """
        if not client_updates:
            return
        
        # Extract weights and sizes
        weights = [u['weights'] for u in client_updates]
        sizes = [u['dataset_size'] for u in client_updates]
        
        # Aggregate
        new_weights = self.aggregate_weights(weights, sizes)
        
        # Update global model
        if self.global_model is None:
            self.initialize_global_model()
        
        self.global_model.load_state_dict(new_weights)
        self.round_number += 1
        
        # Save updated model
        torch.save(self.global_model, self.model_path)
        
        return {
            'round': self.round_number,
            'clients': len(client_updates),
            'avg_accuracy': sum(u['accuracy'] for u in client_updates) / len(client_updates)
        }
    
    def compute_model_hash(self, weights: Dict[str, torch.Tensor]) -> str:
        """Compute hash of model weights for verification"""
        # Serialize weights
        serialized = json.dumps({
            k: v.cpu().numpy().tolist() if isinstance(v, torch.Tensor) else v
            for k, v in sorted(weights.items())
        }, sort_keys=True)
        
        return hashlib.sha256(serialized.encode()).hexdigest()
    
    def verify_client_update(self, update: Dict[str, Any]) -> bool:
        """Verify client update integrity"""
        required_keys = ['weights', 'dataset_size', 'client_id', 'accuracy']
        
        # Check required fields
        if not all(k in update for k in required_keys):
            return False
        
        # Check dataset size is positive
        if update['dataset_size'] <= 0:
            return False
        
        # Check accuracy is valid
        if not (0 <= update['accuracy'] <= 1):
            return False
        
        return True
    
    def get_status(self) -> Dict[str, Any]:
        """Get federated learning status"""
        return {
            'round': self.round_number,
            'global_model_loaded': self.global_model is not None,
            'model_path': str(self.model_path),
            'clients_registered': len(self.client_models)
        }


class FederatedClient:
    """Client-side federated learning"""
    
    def __init__(self, client_id: str, local_data_path: str):
        self.client_id = client_id
        self.local_data_path = Path(local_data_path)
        self.local_model = None
        
    def load_global_weights(self, weights: Dict[str, torch.Tensor]):
        """Load global model weights"""
        if self.local_model is None:
            # Initialize local model with same architecture
            from modules.ml_engine.sentinel_net import SentinelThreatNet
            self.local_model = SentinelThreatNet()
        
        self.local_model.load_state_dict(weights)
    
    def train_local_model(self, epochs: int = 5, lr: float = 0.001) -> Dict[str, Any]:
        """
        Train on local data
        Returns: weights + metadata
        """
        if self.local_model is None:
            raise ValueError("Load global weights first")
        
        # Load local training data
        train_data = self._load_local_data()
        
        # Train
        optimizer = torch.optim.Adam(self.local_model.parameters(), lr=lr)
        criterion = nn.CrossEntropyLoss()
        
        self.local_model.train()
        total_loss = 0
        correct = 0
        total = 0
        
        for epoch in range(epochs):
            for batch in train_data:
                inputs, labels = batch
                
                optimizer.zero_grad()
                outputs = self.local_model(inputs)
                loss = criterion(outputs, labels)
                loss.backward()
                optimizer.step()
                
                total_loss += loss.item()
                _, predicted = outputs.max(1)
                total += labels.size(0)
                correct += predicted.eq(labels).sum().item()
        
        accuracy = correct / total if total > 0 else 0
        
        return {
            'weights': self.local_model.state_dict(),
            'dataset_size': total,
            'client_id': self.client_id,
            'accuracy': accuracy,
            'loss': total_loss / (epochs * len(train_data)) if len(train_data) > 0 else 0
        }
    
    def _load_local_data(self):
        """Load local training data (placeholder)"""
        # TODO: Implement actual data loading
        return []


if __name__ == "__main__":
    # Test federated trainer
    trainer = FederatedTrainer()
    
    try:
        trainer.initialize_global_model()
        print("✓ Global model loaded")
        
        status = trainer.get_status()
        print(f"✓ Status: {status}")
        
        # Simulate client updates
        dummy_weights = trainer.get_global_weights()
        client_updates = [
            {
                'weights': dummy_weights,
                'dataset_size': 100,
                'client_id': 'client_1',
                'accuracy': 0.85
            },
            {
                'weights': dummy_weights,
                'dataset_size': 150,
                'client_id': 'client_2',
                'accuracy': 0.88
            }
        ]
        
        result = trainer.update_global_model(client_updates)
        print(f"✓ Aggregation: {result}")
        
    except Exception as e:
        print(f"✗ Error: {e}")
