"""
Container escape detection using container boundary violations.
"""
import numpy as np
from typing import Dict, Any, Tuple
from .base_detector import BaseDetector

class ContainerEscapeDetector(BaseDetector):
    """Detects container escape attempts."""
    
    ESCAPE_INDICATORS = [
        'docker.sock', '/var/run/docker.sock',
        'hostPID', 'hostNetwork', 'hostIPC', 'hostPath',
        'privileged', '--privileged',
        'nsenter', 'unshare', '/proc/1/', 'runc', 'ctr'
    ]
    
    DANGEROUS_MOUNTS = [
        '/var/run/docker.sock', '/host', '/proc', '/sys',
        '/dev', '/etc/kubernetes'
    ]
    
    CAPABILITY_ESCALATIONS = [
        'CAP_SYS_ADMIN', 'CAP_SYS_PTRACE', 'CAP_SYS_MODULE',
        'CAP_DAC_READ_SEARCH', 'CAP_DAC_OVERRIDE'
    ]
    
    def __init__(self):
        super().__init__("escape_detector")
        # This is primarily rule-based due to specific nature of escapes
        self.trained = True  # Always ready
    
    def extract_features(self, event: Dict[str, Any]) -> np.ndarray:
        """Extract container boundary features.
        
        Features:
        1. Escape indicator count
        2. Docker socket access flag
        3. HostPath mount flag
        4. Privileged flag
        5. Process count
        6. Open files (scaled)
        """
        details = event.get('details', {})
        event_str = str(event).lower()
        
        features = [
            sum(1 for indicator in self.ESCAPE_INDICATORS if indicator in event_str),
            1 if details.get('docker_sock_access') or 'docker.sock' in event_str else 0,
            1 if 'hostpath' in event_str or 'hostpid' in event_str else 0,
            1 if 'privileged' in event_str else 0,
            details.get('process_count', 1),
            details.get('open_files', 0) / 10
        ]
        return np.array(features)
    
    def train(self, training_data: np.ndarray):
        """No training needed for rule-based detector."""
        self.trained = True
        self.save_model()
    
    def predict(self, event: Dict[str, Any]) -> Tuple[bool, float]:
        """Predict if event is container escape attempt."""
        event_str = str(event).lower()
        details = event.get('details', {})
        command = str(details.get('command', '')).lower()
        
        # Critical escape attempts (highest confidence)
        critical = [
            'docker.sock' in event_str or '/var/run/docker.sock' in event_str,
            'nsenter' in command and ('--target' in command or '-t' in command),
            details.get('docker_sock_access', False),
            'privileged' in event_str and ('true' in event_str or 'securitycontext' in event_str)
        ]
        
        if any(critical):
            return True, 0.95
        
        # Dangerous mounts
        dangerous_mount = any(mount in event_str for mount in self.DANGEROUS_MOUNTS)
        if dangerous_mount:
            return True, 0.90
        
        # Capability escalations
        capability_match = any(cap in event_str for cap in self.CAPABILITY_ESCALATIONS)
        if capability_match:
            return True, 0.85
        
        # Count escape indicators
        matches = sum(1 for indicator in self.ESCAPE_INDICATORS if indicator in event_str)
        
        if matches >= 2:
            return True, min(0.7 + matches * 0.1, 1.0)
        
        return matches >= 1, min(matches * 0.5, 1.0)