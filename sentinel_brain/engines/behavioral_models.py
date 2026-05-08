"""
Behavioral Intelligence Engine - Phase 2 ML Models
Production-grade: PyTorch LSTM, sklearn IsolationForest, PyTorch Autoencoder
"""
import numpy as np
import json
import pickle
import logging
from pathlib import Path
from collections import defaultdict

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
import joblib

logger = logging.getLogger(__name__)

FEATURE_DIM = 10  # number of features per request

# ─── Feature Extraction ───────────────────────────────────────────────────────

def features_to_vector(features: dict) -> list:
    """Convert feature dict to fixed-length numeric vector (FEATURE_DIM=10)"""
    status = float(features.get('status_code', 200))
    return [
        float(features.get('url_length', 0)) / 500.0,
        float(features.get('param_count', 0)) / 20.0,
        float(features.get('header_count', 0)) / 30.0,
        float(features.get('user_agent_length', 0)) / 200.0,
        float(features.get('request_size', 0)) / 10000.0,
        float(features.get('response_size', 0)) / 50000.0,
        float(features.get('response_time', 0)) / 5.0,
        status / 500.0,
        1.0 if features.get('has_params') else 0.0,
        1.0 if status >= 400 else 0.0,  # is_error
    ]


# ─── PyTorch LSTM Autoencoder ─────────────────────────────────────────────────

class LSTMAutoencoder(nn.Module):
    """
    Sequence autoencoder: encodes request sequence → latent → reconstructs.
    High reconstruction error = anomalous sequence.
    """
    def __init__(self, input_dim: int = FEATURE_DIM, hidden_dim: int = 32, latent_dim: int = 16, num_layers: int = 2):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        self.encoder = nn.LSTM(input_dim, hidden_dim, num_layers=num_layers,
                               batch_first=True, dropout=0.2)
        self.enc_to_latent = nn.Linear(hidden_dim, latent_dim)

        self.latent_to_dec = nn.Linear(latent_dim, hidden_dim)
        self.decoder = nn.LSTM(hidden_dim, hidden_dim, num_layers=num_layers,
                               batch_first=True, dropout=0.2)
        self.output_layer = nn.Linear(hidden_dim, input_dim)

    def forward(self, x):
        # x: (batch, seq_len, input_dim)
        _, (h_n, _) = self.encoder(x)
        latent = torch.relu(self.enc_to_latent(h_n[-1]))  # (batch, latent_dim)

        # Decode: repeat latent across seq_len
        seq_len = x.size(1)
        dec_input = torch.relu(self.latent_to_dec(latent))  # (batch, hidden_dim)
        dec_input = dec_input.unsqueeze(1).repeat(1, seq_len, 1)  # (batch, seq_len, hidden_dim)

        dec_out, _ = self.decoder(dec_input)
        return self.output_layer(dec_out)  # (batch, seq_len, input_dim)


class SentinelLSTMAutoencoder:
    """Wrapper: trains LSTMAutoencoder, scores sequences, persists model."""

    def __init__(self, input_dim: int = FEATURE_DIM, hidden_dim: int = 32,
                 latent_dim: int = 16, seq_len: int = 10):
        self.seq_len = seq_len
        self.input_dim = input_dim
        self.model = LSTMAutoencoder(input_dim, hidden_dim, latent_dim)
        self.threshold = 0.05
        self.fitted = False
        self.device = torch.device('cpu')

    def _pad_or_trim(self, seq: list) -> np.ndarray:
        """Pad/trim sequence to fixed seq_len"""
        arr = np.array(seq, dtype=np.float32)
        if len(arr) >= self.seq_len:
            return arr[-self.seq_len:]
        pad = np.zeros((self.seq_len - len(arr), self.input_dim), dtype=np.float32)
        return np.vstack([pad, arr])

    def fit(self, sequences: list, epochs: int = 30, batch_size: int = 32, lr: float = 1e-3):
        """sequences: list of lists of feature vectors"""
        valid = [s for s in sequences if len(s) >= 3]
        if len(valid) < 5:
            logger.warning(f"LSTM: not enough sequences ({len(valid)}), need 5+")
            return False

        X = np.stack([self._pad_or_trim(s) for s in valid])  # (N, seq_len, input_dim)
        tensor = torch.tensor(X, dtype=torch.float32)
        loader = DataLoader(TensorDataset(tensor), batch_size=batch_size, shuffle=True)

        self.model.train()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        for epoch in range(epochs):
            total_loss = 0.0
            for (batch,) in loader:
                optimizer.zero_grad()
                recon = self.model(batch)
                loss = criterion(recon, batch)
                loss.backward()
                nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                optimizer.step()
                total_loss += loss.item()
            if (epoch + 1) % 10 == 0:
                logger.debug(f"LSTM epoch {epoch+1}/{epochs} loss={total_loss/len(loader):.4f}")

        # Set threshold = mean + 2*std of reconstruction errors on training data
        self.model.eval()
        with torch.no_grad():
            recon = self.model(tensor)
            errors = torch.mean((recon - tensor) ** 2, dim=(1, 2)).numpy()
        self.threshold = float(np.mean(errors) + 2 * np.std(errors))
        self.fitted = True
        logger.info(f"LSTM Autoencoder fitted on {len(valid)} sequences, threshold={self.threshold:.5f}")
        return True

    def reconstruction_error(self, sequence: list) -> float:
        if not self.fitted or len(sequence) < 2:
            return 0.0
        x = torch.tensor(self._pad_or_trim(sequence), dtype=torch.float32).unsqueeze(0)
        self.model.eval()
        with torch.no_grad():
            recon = self.model(x)
            error = torch.mean((recon - x) ** 2).item()
        return float(error)

    def score(self, sequence: list) -> float:
        """Normalized anomaly score 0-1"""
        err = self.reconstruction_error(sequence)
        return float(min(err / max(self.threshold, 1e-8), 1.0))

    def is_anomaly(self, sequence: list) -> bool:
        return self.reconstruction_error(sequence) > self.threshold


# ─── sklearn Isolation Forest ─────────────────────────────────────────────────

class SentinelIsolationForest:
    """
    sklearn IsolationForest with StandardScaler pipeline.
    Detects anomalous individual HTTP requests.
    """

    def __init__(self, n_estimators: int = 200, contamination: float = 0.05,
                 max_features: float = 1.0, random_state: int = 42):
        self.pipeline = Pipeline([
            ('scaler', StandardScaler()),
            ('iforest', IsolationForest(
                n_estimators=n_estimators,
                contamination=contamination,
                max_features=max_features,
                random_state=random_state,
                n_jobs=-1,
            ))
        ])
        self.fitted = False

    def fit(self, X: np.ndarray):
        if len(X) < 20:
            logger.warning(f"IsolationForest: need 20+ samples, got {len(X)}")
            return False
        self.pipeline.fit(X)
        self.fitted = True
        logger.info(f"IsolationForest fitted on {len(X)} samples")
        return True

    def score(self, x: np.ndarray) -> float:
        """Anomaly score 0-1 (higher = more anomalous)"""
        if not self.fitted:
            return 0.0
        x = np.array(x, dtype=float).reshape(1, -1)
        # decision_function: negative = anomaly, positive = normal
        raw = self.pipeline.decision_function(x)[0]
        # Normalize to 0-1: anomaly score = 1 - sigmoid(raw * 2)
        score = 1.0 / (1.0 + np.exp(raw * 2))
        return float(np.clip(score, 0.0, 1.0))

    def is_anomaly(self, x: np.ndarray) -> bool:
        if not self.fitted:
            return False
        x = np.array(x, dtype=float).reshape(1, -1)
        return self.pipeline.predict(x)[0] == -1


# ─── PyTorch Request-Level Autoencoder ────────────────────────────────────────

class RequestAutoencoder(nn.Module):
    """Single-request autoencoder for normal behavior baseline."""
    def __init__(self, input_dim: int = FEATURE_DIM):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 32),
            nn.ReLU(),
            nn.Linear(32, 16),
            nn.ReLU(),
            nn.Linear(16, 8),
        )
        self.decoder = nn.Sequential(
            nn.Linear(8, 16),
            nn.ReLU(),
            nn.Linear(16, 32),
            nn.ReLU(),
            nn.Linear(32, input_dim),
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))


class SentinelAutoencoder:
    """Wrapper: trains RequestAutoencoder on normal traffic, scores single requests."""

    def __init__(self, input_dim: int = FEATURE_DIM):
        self.model = RequestAutoencoder(input_dim)
        self.threshold = 0.05
        self.fitted = False

    def fit(self, X: np.ndarray, epochs: int = 100, batch_size: int = 64, lr: float = 1e-3):
        if len(X) < 10:
            logger.warning(f"Autoencoder: need 10+ samples, got {len(X)}")
            return False

        tensor = torch.tensor(X, dtype=torch.float32)
        loader = DataLoader(TensorDataset(tensor), batch_size=batch_size, shuffle=True)

        self.model.train()
        optimizer = optim.Adam(self.model.parameters(), lr=lr)
        criterion = nn.MSELoss()

        for epoch in range(epochs):
            for (batch,) in loader:
                optimizer.zero_grad()
                loss = criterion(self.model(batch), batch)
                loss.backward()
                optimizer.step()

        # Threshold = mean + 2*std of training reconstruction errors
        self.model.eval()
        with torch.no_grad():
            recon = self.model(tensor)
            errors = torch.mean((recon - tensor) ** 2, dim=1).numpy()
        self.threshold = float(np.mean(errors) + 2 * np.std(errors))
        self.fitted = True
        logger.info(f"Autoencoder fitted on {len(X)} samples, threshold={self.threshold:.5f}")
        return True

    def reconstruction_error(self, x: np.ndarray) -> float:
        if not self.fitted:
            return 0.0
        t = torch.tensor(np.array(x, dtype=np.float32)).unsqueeze(0)
        self.model.eval()
        with torch.no_grad():
            return float(torch.mean((self.model(t) - t) ** 2).item())

    def score(self, x: np.ndarray) -> float:
        err = self.reconstruction_error(x)
        return float(min(err / max(self.threshold, 1e-8), 1.0))

    def is_anomaly(self, x: np.ndarray) -> bool:
        return self.reconstruction_error(x) > self.threshold


# ─── Model Manager ────────────────────────────────────────────────────────────

class BehavioralModelManager:
    """
    Manages all Phase 2 ML models.
    - SentinelIsolationForest  : per-request anomaly (sklearn)
    - SentinelAutoencoder      : per-request reconstruction (PyTorch)
    - SentinelLSTMAutoencoder  : per-session sequence anomaly (PyTorch LSTM)
    """

    MODEL_PATH = Path("models/ml_engine/behavioral_models.pkl")

    def __init__(self):
        self.iso_forest = SentinelIsolationForest()
        self.autoencoder = SentinelAutoencoder()
        self.lstm = SentinelLSTMAutoencoder()
        self._load_if_exists()

    def _load_if_exists(self):
        if self.MODEL_PATH.exists():
            try:
                state = joblib.load(self.MODEL_PATH)
                self.iso_forest = state.get('iso_forest', self.iso_forest)
                self.autoencoder = state.get('autoencoder', self.autoencoder)
                self.lstm = state.get('lstm', self.lstm)
                logger.info("Behavioral models loaded from disk")
            except Exception as e:
                logger.warning(f"Could not load behavioral models: {e}")

    def save(self):
        self.MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            'iso_forest': self.iso_forest,
            'autoencoder': self.autoencoder,
            'lstm': self.lstm,
        }, self.MODEL_PATH, compress=3)
        logger.info(f"Behavioral models saved → {self.MODEL_PATH}")

    def train(self, traffic_rows: list) -> tuple:
        """
        Train all models from traffic_log rows.
        Returns (success: bool, message: str)
        """
        vectors = []
        sequences_by_session = defaultdict(list)

        for row in traffic_rows:
            # Support both dict rows and sqlite tuple rows
            raw = row.get('features') if isinstance(row, dict) else (row[14] if len(row) > 14 else None)
            session = (row.get('session_id') if isinstance(row, dict) else row[11]) or 'default'

            if isinstance(raw, str):
                try:
                    feat = json.loads(raw)
                except Exception:
                    continue
            elif isinstance(raw, dict):
                feat = raw
            else:
                continue

            vec = features_to_vector(feat)
            vectors.append(vec)
            sequences_by_session[session].append(vec)

        if len(vectors) < 20:
            return False, f"Not enough data: {len(vectors)} samples (need 20+)"

        X = np.array(vectors, dtype=np.float32)

        # Train all three models
        iso_ok = self.iso_forest.fit(X)
        ae_ok = self.autoencoder.fit(X)

        sequences = [s for s in sequences_by_session.values() if len(s) >= 3]
        lstm_ok = self.lstm.fit(sequences) if sequences else False

        if iso_ok or ae_ok:
            self.save()

        msg = (f"Trained on {len(vectors)} samples, {len(sequences)} sequences | "
               f"IsoForest={'✓' if iso_ok else '✗'} "
               f"Autoencoder={'✓' if ae_ok else '✗'} "
               f"LSTM={'✓' if lstm_ok else '✗'}")
        logger.info(msg)
        return True, msg

    def score_request(self, features: dict, session_sequence: list = None) -> dict:
        """
        Score a single request against all models.
        Returns dict with per-model scores and combined verdict.
        """
        vec = np.array(features_to_vector(features), dtype=np.float32)

        iso_score = self.iso_forest.score(vec)
        ae_score = self.autoencoder.score(vec)

        lstm_score = 0.0
        if self.lstm.fitted and session_sequence and len(session_sequence) >= 3:
            lstm_score = self.lstm.score(session_sequence)

        # Weighted combination — LSTM gets more weight when available
        if self.lstm.fitted and lstm_score > 0:
            combined = 0.30 * iso_score + 0.25 * ae_score + 0.45 * lstm_score
        else:
            combined = 0.55 * iso_score + 0.45 * ae_score

        return {
            'isolation_forest': round(iso_score, 3),
            'autoencoder': round(ae_score, 3),
            'lstm': round(lstm_score, 3),
            'combined': round(combined, 3),
            'is_anomaly': combined > 0.65,
        }

    def get_status(self) -> dict:
        return {
            'isolation_forest_fitted': self.iso_forest.fitted,
            'autoencoder_fitted': self.autoencoder.fitted,
            'lstm_fitted': self.lstm.fitted,
            'lstm_threshold': round(self.lstm.threshold, 5),
            'ae_threshold': round(self.autoencoder.threshold, 5),
            'model_path': str(self.MODEL_PATH),
            'model_exists': self.MODEL_PATH.exists(),
        }
