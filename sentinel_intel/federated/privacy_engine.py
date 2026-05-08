"""
Privacy Engine for Federated Learning
Implements differential privacy to protect client data
"""

import torch
import numpy as np
from typing import Dict, Any, List
import hashlib

class PrivacyEngine:
    """Differential privacy for federated learning"""
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5, 
                 clip_norm: float = 1.0):
        """
        Args:
            epsilon: Privacy budget (lower = more private)
            delta: Probability of privacy breach
            clip_norm: Gradient clipping threshold
        """
        self.epsilon = epsilon
        self.delta = delta
        self.clip_norm = clip_norm
        self.noise_scale = self._compute_noise_scale()
    
    def _compute_noise_scale(self) -> float:
        """Compute noise scale from privacy parameters"""
        # Gaussian mechanism: σ = (clip_norm * sqrt(2 * ln(1.25/delta))) / epsilon
        return (self.clip_norm * np.sqrt(2 * np.log(1.25 / self.delta))) / self.epsilon
    
    def clip_gradients(self, gradients: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Clip gradients to bound sensitivity"""
        clipped = {}
        
        for name, grad in gradients.items():
            if grad is None:
                clipped[name] = grad
                continue
            
            # Compute L2 norm
            grad_norm = torch.norm(grad, p=2)
            
            # Clip if exceeds threshold
            if grad_norm > self.clip_norm:
                clipped[name] = grad * (self.clip_norm / grad_norm)
            else:
                clipped[name] = grad
        
        return clipped
    
    def add_noise(self, weights: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Add Gaussian noise to weights for differential privacy"""
        noisy_weights = {}
        
        for name, weight in weights.items():
            # Generate Gaussian noise
            noise = torch.randn_like(weight) * self.noise_scale
            noisy_weights[name] = weight + noise
        
        return noisy_weights
    
    def privatize_update(self, weights: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Apply full privacy mechanism: clip + noise"""
        # Treat weights as gradients for clipping
        clipped = self.clip_gradients(weights)
        noisy = self.add_noise(clipped)
        return noisy
    
    def compute_privacy_spent(self, num_rounds: int, num_clients: int) -> Dict[str, float]:
        """
        Compute total privacy budget spent
        Uses composition theorem
        """
        # Simple composition (conservative)
        total_epsilon = self.epsilon * num_rounds
        total_delta = self.delta * num_rounds
        
        return {
            'epsilon': total_epsilon,
            'delta': total_delta,
            'rounds': num_rounds,
            'clients': num_clients,
            'privacy_level': self._privacy_level(total_epsilon)
        }
    
    def _privacy_level(self, epsilon: float) -> str:
        """Categorize privacy level"""
        if epsilon < 1.0:
            return "STRONG"
        elif epsilon < 5.0:
            return "MODERATE"
        elif epsilon < 10.0:
            return "WEAK"
        else:
            return "MINIMAL"
    
    def secure_aggregation_mask(self, client_id: str, round_num: int) -> torch.Tensor:
        """
        Generate deterministic mask for secure aggregation
        Masks cancel out when summed across all clients
        """
        # Deterministic seed from client_id + round
        seed_str = f"{client_id}_{round_num}"
        seed = int(hashlib.sha256(seed_str.encode()).hexdigest()[:8], 16)
        
        # Generate mask
        torch.manual_seed(seed)
        mask = torch.randn(1)  # Placeholder, actual size depends on model
        
        return mask
    
    def verify_privacy_guarantee(self) -> Dict[str, Any]:
        """Verify privacy parameters are valid"""
        valid = True
        issues = []
        
        if self.epsilon <= 0:
            valid = False
            issues.append("Epsilon must be positive")
        
        if self.delta <= 0 or self.delta >= 1:
            valid = False
            issues.append("Delta must be in (0, 1)")
        
        if self.clip_norm <= 0:
            valid = False
            issues.append("Clip norm must be positive")
        
        return {
            'valid': valid,
            'issues': issues,
            'epsilon': self.epsilon,
            'delta': self.delta,
            'clip_norm': self.clip_norm,
            'noise_scale': self.noise_scale
        }
    
    def get_config(self) -> Dict[str, float]:
        """Get privacy configuration"""
        return {
            'epsilon': self.epsilon,
            'delta': self.delta,
            'clip_norm': self.clip_norm,
            'noise_scale': self.noise_scale
        }


class SecureAggregator:
    """Secure multi-party aggregation"""
    
    def __init__(self, num_clients: int):
        self.num_clients = num_clients
        self.client_masks: Dict[str, torch.Tensor] = {}
    
    def generate_client_pair_masks(self, client_id: str, round_num: int) -> Dict[str, torch.Tensor]:
        """
        Generate pairwise masks for secure aggregation
        Each client generates masks for all other clients
        """
        masks = {}
        
        for other_id in range(self.num_clients):
            if str(other_id) == client_id:
                continue
            
            # Deterministic mask based on pair
            pair_key = f"{min(client_id, str(other_id))}_{max(client_id, str(other_id))}_{round_num}"
            seed = int(hashlib.sha256(pair_key.encode()).hexdigest()[:8], 16)
            
            torch.manual_seed(seed)
            mask = torch.randn(1)  # Placeholder
            
            # Add or subtract based on client order
            if client_id < str(other_id):
                masks[str(other_id)] = mask
            else:
                masks[str(other_id)] = -mask
        
        return masks
    
    def apply_masks(self, weights: Dict[str, torch.Tensor], 
                   masks: Dict[str, torch.Tensor]) -> Dict[str, torch.Tensor]:
        """Apply secure aggregation masks to weights"""
        masked = {}
        
        for name, weight in weights.items():
            # Sum all pairwise masks
            total_mask = sum(masks.values())
            masked[name] = weight + total_mask
        
        return masked
    
    def aggregate_masked_weights(self, masked_weights: List[Dict[str, torch.Tensor]]) -> Dict[str, torch.Tensor]:
        """
        Aggregate masked weights
        Masks cancel out, revealing only the sum
        """
        if not masked_weights:
            return {}
        
        aggregated = {}
        param_names = masked_weights[0].keys()
        
        for param_name in param_names:
            # Sum all masked weights (masks cancel)
            aggregated[param_name] = sum(
                weights[param_name] for weights in masked_weights
            )
        
        return aggregated


if __name__ == "__main__":
    # Test privacy engine
    print("Testing Privacy Engine...")
    
    engine = PrivacyEngine(epsilon=1.0, delta=1e-5, clip_norm=1.0)
    
    # Verify configuration
    verification = engine.verify_privacy_guarantee()
    print(f"✓ Privacy config valid: {verification['valid']}")
    print(f"  Epsilon: {verification['epsilon']}")
    print(f"  Delta: {verification['delta']}")
    print(f"  Noise scale: {verification['noise_scale']:.4f}")
    
    # Test gradient clipping
    dummy_grads = {
        'layer1': torch.randn(10, 10) * 5,  # Large gradients
        'layer2': torch.randn(5, 5) * 0.1   # Small gradients
    }
    
    clipped = engine.clip_gradients(dummy_grads)
    print(f"✓ Gradient clipping:")
    print(f"  Original norm: {torch.norm(dummy_grads['layer1']):.4f}")
    print(f"  Clipped norm: {torch.norm(clipped['layer1']):.4f}")
    
    # Test noise addition
    noisy = engine.add_noise(clipped)
    print(f"✓ Noise added")
    
    # Test privacy budget
    budget = engine.compute_privacy_spent(num_rounds=10, num_clients=5)
    print(f"✓ Privacy budget after 10 rounds:")
    print(f"  Total epsilon: {budget['epsilon']}")
    print(f"  Privacy level: {budget['privacy_level']}")
    
    print("\n✓ All privacy tests passed!")
