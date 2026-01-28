"""
Base class for all ML-based threat detectors.
"""
import pickle
import os
from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple, Optional
import numpy as np
import structlog

log = structlog.get_logger()

class BaseDetector(ABC):
    """Base class for all threat detectors."""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.model = None
        self.trained = False
        self.model_path = f"ml_models/trained_models/{model_name}.pkl"
        
        # Try to load pre-trained model
        self.load_model()
    
    @abstractmethod
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract features from event. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    def train(self, training_data: np.ndarray):
        """Train the model. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is malicious. Returns (is_threat, confidence_score)."""
        pass
    
    def save_model(self):
        """Save trained model to disk."""
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        with open(self.model_path, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'trained': self.trained,
                'model_name': self.model_name,
                'version': '1.0.0'
            }, f)
        log.info(f"Model saved", model=self.model_name, path=self.model_path)
    
    def load_model(self):
        """Load pre-trained model from disk."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                    self.model = data['model']
                    self.trained = data['trained']
                log.info(f"Loaded pre-trained model", model=self.model_name)
            except Exception as e:
                log.warning(f"Failed to load model", model=self.model_name, error=str(e))
        else:
            log.info(f"No pre-trained model found", model=self.model_name)
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the model."""
        return {
            'name': self.model_name,
            'trained': self.trained,
            'model_type': type(self.model).__name__ if self.model else None,
            'path': self.model_path
        }