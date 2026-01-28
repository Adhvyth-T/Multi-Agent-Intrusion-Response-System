# collectors/__init__.py
"""
Event Collectors - Pluggable monitoring backends.
"""

from collectors.base_collector import BaseEventCollector, CollectorHealth, CollectorMetrics
from collectors.docker_collector import DockerEventCollector
from collectors.falco_collector import FalcoCollector
from collectors.kubernetes_collector import KubernetesCollector
from collectors.collector_factory import CollectorFactory

__all__ = [
    'BaseEventCollector',
    'CollectorHealth',
    'CollectorMetrics',
    'DockerEventCollector',
    'FalcoCollector',
    'KubernetesCollector',
    'CollectorFactory',
]