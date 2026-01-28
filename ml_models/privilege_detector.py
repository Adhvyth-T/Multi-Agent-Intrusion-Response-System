"""
Privilege escalation detection using command patterns.
"""
import numpy as np
from sklearn.svm import OneClassSVM
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class PrivilegeDetector(BaseDetector):
    """Detects privilege escalation attempts."""
    
    ESCALATION_PATTERNS = [
        'sudo', 'su -', 'su root', 'chmod 777', 'chmod 666', 'chmod +s',
        'chown root', 'setuid', 'setgid', 'pkexec', 'doas'
    ]
    
    SENSITIVE_FILES = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/sudoers.d',
        '/root/.ssh', '/etc/crontab', '/etc/cron.d'
    ]
    
    SENSITIVE_PATHS = ['/root', '/etc', '/proc/sys', '/sys', '/boot']
    
    DANGEROUS_COMMANDS = [
        'passwd root', 'usermod -a', 'useradd', 'adduser',
        'visudo', 'chmod u+s', 'chmod g+s'
    ]
    
    def __init__(self):
        super().__init__("privilege_detector")
        if not self.trained:
            self.model = OneClassSVM(
                kernel='rbf',
                gamma='auto',
                nu=0.1  # Expected outlier fraction
            )
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract privilege-related features.
        
        Features:
        1. Escalation pattern count
        2. Sensitive path count
        3. Root access flag
        4. Permission modification flag (777, 666)
        5. chmod/chown flag
        6. CPU usage
        7. Process count
        8. Command complexity
        """
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        process = str(details.get('process', '')).lower()
        
        features = [
            sum(1 for pattern in self.ESCALATION_PATTERNS if pattern in command),
            sum(1 for path in self.SENSITIVE_PATHS if path in command),
            1 if 'root' in command or 'root' in process else 0,
            1 if '777' in command or '666' in command else 0,
            1 if 'chmod' in command or 'chown' in command else 0,
            details.get('cpu_usage', 0),
            details.get('process_count', 1),
            len(command.split()) / 5  # Command complexity
        ]
        return np.array(features)
    
    def train(self, training_data: np.ndarray):
        """Train on normal (non-privileged) commands."""
        self.model.fit(training_data)
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is privilege escalation."""
        command = str(event.get('details', {}).get('command', '')).lower()
        
        # Strong heuristic check (always applied)
        critical_indicators = [
            '/etc/shadow' in command,
            '/etc/passwd' in command and 'cat' not in command,
            'sudo chmod 777' in command,
            'setuid' in command and '0' in command,
            any(dangerous in command for dangerous in self.DANGEROUS_COMMANDS)
        ]
        
        if any(critical_indicators):
            return True, 0.95
        
        # Check for sensitive file access
        sensitive_file_access = any(file in command for file in self.SENSITIVE_FILES)
        if sensitive_file_access:
            return True, 0.85
        
        if not self.trained:
            # Fallback to pattern matching
            matches = sum(1 for pattern in self.ESCALATION_PATTERNS if pattern in command)
            return matches >= 2, min(matches * 0.3, 1.0)
        
        features = self.extract_features(event)
        prediction = self.model.predict(features.reshape(1, -1))[0]
        score = -self.model.score_samples(features.reshape(1, -1))[0]
        
        return prediction == -1, min(score, 1.0)