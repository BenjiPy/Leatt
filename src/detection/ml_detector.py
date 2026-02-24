"""Machine Learning-based anomaly detection using Isolation Forest."""

import time
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field
from collections import deque
import threading

from ..utils.logger import get_logger
from ..utils.config import get_config

logger = get_logger("ml_detector")


@dataclass
class FeatureVector:
    """Feature vector for ML model input."""
    timestamp: float
    process_name: str
    
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    num_connections: int = 0
    bytes_sent_delta: int = 0
    bytes_recv_delta: int = 0
    io_read_delta: int = 0
    io_write_delta: int = 0
    file_accesses: int = 0
    sensitive_file_accesses: int = 0
    unique_destinations: int = 0
    process_age_seconds: float = 0.0
    
    def to_array(self) -> list[float]:
        """Convert to feature array for model input."""
        return [
            self.cpu_percent,
            self.memory_percent,
            float(self.num_connections),
            float(self.bytes_sent_delta) / 1024,
            float(self.bytes_recv_delta) / 1024,
            float(self.io_read_delta) / 1024,
            float(self.io_write_delta) / 1024,
            float(self.file_accesses),
            float(self.sensitive_file_accesses) * 10,
            float(self.unique_destinations),
            min(self.process_age_seconds / 3600, 24),
        ]


class MLAnomalyDetector:
    """
    Anomaly detection using Isolation Forest algorithm.
    
    Learns normal behavior patterns and flags anomalies.
    """
    
    def __init__(self, model_path: Optional[Path] = None):
        self.config = get_config()
        
        if model_path:
            self.model_path = model_path
        else:
            self.model_path = Path(__file__).parent.parent.parent / "data" / "models" / "anomaly_detector.joblib"
        
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._model = None
        self._scaler = None
        self._is_trained = False
        
        self._training_data: deque[list[float]] = deque(maxlen=10000)
        self._min_samples = self.config.get("ml.min_samples_for_training", 1000)
        
        self._feature_buffer: dict[int, list[FeatureVector]] = {}
        
        self._lock = threading.Lock()
        
        self._sklearn_available = self._check_sklearn()
        
        if self._sklearn_available:
            self._load_model()
    
    def _check_sklearn(self) -> bool:
        """Check if scikit-learn is available."""
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.preprocessing import StandardScaler
            import joblib
            return True
        except ImportError:
            logger.warning("scikit-learn not available, ML detection disabled")
            return False
    
    def _load_model(self) -> bool:
        """Load trained model from disk."""
        if not self._sklearn_available:
            return False
        
        try:
            import joblib
            
            if self.model_path.exists():
                data = joblib.load(self.model_path)
                self._model = data.get("model")
                self._scaler = data.get("scaler")
                self._is_trained = True
                logger.info(f"Loaded ML model from {self.model_path}")
                return True
        except Exception as e:
            logger.warning(f"Failed to load ML model: {e}")
        
        return False
    
    def _save_model(self) -> bool:
        """Save trained model to disk."""
        if not self._sklearn_available or not self._is_trained:
            return False
        
        try:
            import joblib
            
            joblib.dump({
                "model": self._model,
                "scaler": self._scaler,
            }, self.model_path)
            
            logger.info(f"Saved ML model to {self.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save ML model: {e}")
            return False
    
    def _create_model(self):
        """Create a new Isolation Forest model."""
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler
        
        self._model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        
        self._scaler = StandardScaler()
    
    def train(self, force: bool = False) -> bool:
        """
        Train the model on collected samples.
        
        Args:
            force: Train even if minimum samples not reached
        
        Returns:
            True if training was successful
        """
        if not self._sklearn_available:
            return False
        
        with self._lock:
            sample_count = len(self._training_data)
            
            if not force and sample_count < self._min_samples:
                logger.debug(f"Not enough samples for training: {sample_count}/{self._min_samples}")
                return False
            
            if sample_count == 0:
                logger.warning("No training data available")
                return False
            
            try:
                import numpy as np
                
                self._create_model()
                
                X = np.array(list(self._training_data))
                
                X_scaled = self._scaler.fit_transform(X)
                
                self._model.fit(X_scaled)
                
                self._is_trained = True
                
                self._save_model()
                
                logger.info(f"ML model trained on {sample_count} samples")
                return True
            
            except Exception as e:
                logger.error(f"Failed to train ML model: {e}")
                return False
    
    def add_training_sample(self, features: FeatureVector) -> None:
        """Add a feature vector to training data."""
        with self._lock:
            self._training_data.append(features.to_array())
    
    def predict(self, event: Any) -> float:
        """
        Predict anomaly score for an event.
        
        Args:
            event: MonitorEvent from monitors
        
        Returns:
            Anomaly score between 0 (normal) and 1 (anomalous)
        """
        if not self._sklearn_available or not self._is_trained:
            return 0.0
        
        try:
            features = self._extract_features(event)
            if features is None:
                return 0.0
            
            return self._predict_score(features)
        
        except Exception as e:
            logger.debug(f"Error predicting anomaly score: {e}")
            return 0.0
    
    def _extract_features(self, event: Any) -> Optional[FeatureVector]:
        """Extract feature vector from an event."""
        data = event.data
        
        pid = data.get("pid")
        process_name = data.get("process_name", "unknown")
        
        if pid is None:
            return None
        
        features = FeatureVector(
            timestamp=event.timestamp,
            process_name=process_name,
        )
        
        if event.source == "process_monitor":
            features.cpu_percent = data.get("cpu_percent", 0.0)
            features.memory_percent = data.get("memory_percent", 0.0)
            features.num_connections = data.get("num_connections", 0)
            features.io_read_delta = data.get("read_bytes_delta", 0)
            features.io_write_delta = data.get("write_bytes_delta", 0)
        
        elif event.source == "network_monitor":
            features.bytes_sent_delta = data.get("bytes_uploaded", 0)
            features.unique_destinations = 1 if data.get("remote_address") else 0
        
        elif event.source == "file_monitor":
            features.file_accesses = 1
            if data.get("is_sensitive"):
                features.sensitive_file_accesses = 1
        
        return features
    
    def _predict_score(self, features: FeatureVector) -> float:
        """Get anomaly score for features."""
        import numpy as np
        
        with self._lock:
            X = np.array([features.to_array()])
            
            X_scaled = self._scaler.transform(X)
            
            raw_score = self._model.decision_function(X_scaled)[0]
            
            anomaly_score = max(0.0, min(1.0, -raw_score))
            
            return anomaly_score
    
    def update_incremental(self, features: FeatureVector) -> None:
        """
        Add sample and potentially retrain.
        
        Implements incremental learning by periodically retraining
        on new data.
        """
        self.add_training_sample(features)
        
        if len(self._training_data) % 500 == 0 and len(self._training_data) >= self._min_samples:
            threading.Thread(target=self.train, daemon=True).start()
    
    @property
    def is_trained(self) -> bool:
        """Check if model is trained and ready."""
        return self._is_trained
    
    @property
    def sample_count(self) -> int:
        """Get number of training samples collected."""
        return len(self._training_data)
    
    @property
    def samples_needed(self) -> int:
        """Get number of samples still needed for training."""
        return max(0, self._min_samples - len(self._training_data))
    
    def get_stats(self) -> dict:
        """Get detector statistics."""
        return {
            "is_trained": self._is_trained,
            "sample_count": len(self._training_data),
            "min_samples": self._min_samples,
            "samples_needed": self.samples_needed,
            "model_path": str(self.model_path),
            "sklearn_available": self._sklearn_available,
        }
    
    def reset(self) -> None:
        """Reset the detector (clear model and training data)."""
        with self._lock:
            self._model = None
            self._scaler = None
            self._is_trained = False
            self._training_data.clear()
            self._feature_buffer.clear()
        
        if self.model_path.exists():
            self.model_path.unlink()
        
        logger.info("ML detector reset")
