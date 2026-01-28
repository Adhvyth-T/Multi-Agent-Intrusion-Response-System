"""
ML Models for Autonomous IR System.
Specialized detectors for each threat type.
"""

from .base_detector import BaseDetector
from .cryptominer_detector import CryptominerDetector
from .exfiltration_detector import ExfiltrationDetector
from .privilege_detector import PrivilegeDetector
from .shell_detector import ReverseShellDetector
from .escape_detector import ContainerEscapeDetector
from .network_detector import NetworkAnomalyDetector

__all__ = [
    'BaseDetector',
    'CryptominerDetector',
    'ExfiltrationDetector',
    'PrivilegeDetector',
    'ReverseShellDetector',
    'ContainerEscapeDetector',
    'NetworkAnomalyDetector'
]

__version__ = '1.0.0'