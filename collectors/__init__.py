# collectors/__init__.py
"""
Event Collectors for Autonomous IR System

Security Detection:
- DockerEventCollector, FalcoCollector, KubernetesCollector

Investigation & Forensics:
- LogCollector, NetworkCollector, HostCollector, ForensicCollector
"""

from .base_collector import BaseEventCollector, CollectorMetrics, CollectorHealth
from .docker_collector import DockerEventCollector
from .kubernetes_collector import KubernetesCollector
from .log_collector import LogCollector
from .network_collector import NetworkCollector
from .host_collector import HostCollector
from .forensic_collector import ForensicCollector
from .collector_factory import CollectorFactory, CollectorManager

# Import FalcoCollector if available (Linux environments)
try:
    from .falco_collector import FalcoCollector
    FALCO_AVAILABLE = True
except ImportError:
    FALCO_AVAILABLE = False
    
    # Stub for cross-platform compatibility
    class FalcoCollector:
        @staticmethod
        async def is_available():
            return False

__all__ = [
    'BaseEventCollector',
    'CollectorMetrics',
    'CollectorHealth',
    'DockerEventCollector',
    'KubernetesCollector', 
    'FalcoCollector',
    'LogCollector',
    'NetworkCollector',
    'HostCollector',
    'ForensicCollector',
    'CollectorFactory',
    'CollectorManager',
    'FALCO_AVAILABLE'
]