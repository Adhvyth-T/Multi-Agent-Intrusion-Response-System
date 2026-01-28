"""
Reverse shell detection using connection patterns.
"""
import numpy as np
from sklearn.ensemble import IsolationForest
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class ReverseShellDetector(BaseDetector):
    """Detects reverse shell connections."""
    
    SHELL_PATTERNS = [
        'bash -i', 'sh -i', '/dev/tcp', '/dev/udp',
        'nc -e', 'nc -c', 'ncat -e', 'netcat -e',
        'python -c', 'python3 -c', 'perl -e', 'ruby -e', 'php -r',
        '/bin/sh', '/bin/bash', 'cmd.exe', 'powershell'
    ]
    
    REVERSE_SHELL_INDICATORS = [
        'socket', 'connect', 'pty.spawn', 'subprocess.call',
        'exec', 'system', 'shell=True', '>&', '0>&1'
    ]
    
    def __init__(self):
        super().__init__("shell_detector")
        if not self.trained:
            self.model = IsolationForest(
                contamination=0.05,
                random_state=42,
                n_estimators=100
            )
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract shell-related features.
        
        Features:
        1. Network bytes
        2. Process count
        3. Shell pattern count
        4. Redirection flag (>, <)
        5. Background process flag (&)
        6. Piping flag (|)
        7. CPU usage
        8. Command length (scaled)
        """
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        
        features = [
            details.get('network_bytes', 0) / 1000,
            details.get('process_count', 1),
            sum(1 for pattern in self.SHELL_PATTERNS if pattern in command),
            1 if '>' in command or '<' in command else 0,  # Redirection
            1 if '&' in command else 0,  # Background process
            1 if '|' in command else 0,  # Piping
            details.get('cpu_usage', 0),
            len(command) / 20  # Command length
        ]
        return np.array(features)
    
    def train(self, training_data: np.ndarray):
        """Train on normal network connections."""
        self.model.fit(training_data)
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is reverse shell."""
        command = str(event.get('details', {}).get('command', '')).lower()
        
        # Strong pattern matching
        pattern_matches = sum(1 for pattern in self.SHELL_PATTERNS if pattern in command)
        indicator_matches = sum(1 for indicator in self.REVERSE_SHELL_INDICATORS if indicator in command)
        
        # High-confidence detections
        if '/dev/tcp' in command or '/dev/udp' in command:
            return True, 0.95
        
        if pattern_matches >= 2:
            return True, 0.9
        
        if pattern_matches >= 1 and indicator_matches >= 1:
            return True, 0.85
        
        if not self.trained:
            return pattern_matches >= 1, min(pattern_matches * 0.5, 1.0)
        
        features = self.extract_features(event).reshape(1, -1)
        prediction = self.model.predict(features)[0]
        score = -self.model.score_samples(features)[0]
        
        is_threat = (prediction == -1) or (pattern_matches >= 1)
        confidence = min(score + (0.4 if pattern_matches > 0 else 0), 1.0)
        
        return is_threat, confidence