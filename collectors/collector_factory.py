# collectors/collector_factory.py
"""
Collector factory - Auto-detects best collector for the environment.
"""

import structlog
from typing import Optional
import os

from collectors.base_collector import BaseEventCollector
from collectors.docker_collector import DockerEventCollector
from collectors.falco_collector import FalcoCollector
from collectors.kubernetes_collector import KubernetesCollector

log = structlog.get_logger()


class CollectorFactory:
    """
    Factory for creating the appropriate collector based on environment.
    
    Priority (configurable):
    1. Falco (if available) - Best security visibility
    2. Kubernetes (if in cluster) - Native K8s monitoring
    3. Docker (always works) - Reliable fallback
    """
    
    @staticmethod
    async def create_collector(
        preferred: Optional[str] = None,
        fallback: bool = True
    ) -> BaseEventCollector:
        """
        Create the best available collector.
        
        Args:
            preferred: Force specific collector ('falco', 'kubernetes', 'docker')
            fallback: If preferred unavailable, fall back to next best
            
        Returns:
            BaseEventCollector instance
            
        Raises:
            RuntimeError: If no collectors available
        """
        # Check for environment variable override
        env_collector = os.getenv('IR_COLLECTOR')
        if env_collector:
            preferred = env_collector
            log.info(f"Collector preference from environment: {preferred}")
        
        # If specific collector requested
        if preferred:
            collector = await CollectorFactory._create_specific(preferred)
            if collector:
                return collector
            elif not fallback:
                raise RuntimeError(f"Requested collector '{preferred}' not available")
            else:
                log.warning(f"Requested collector '{preferred}' not available, trying fallback")
        
        # Auto-detect best collector
        log.info("Auto-detecting best collector...")
        
        # Try Falco first (production mode)
        if await FalcoCollector.is_available():
            log.info("✓ Falco available - using production monitoring")
            return FalcoCollector()
        
        # Try Kubernetes (if in cluster)
        if await KubernetesCollector.is_available():
            log.info("✓ Kubernetes available - using K8s API monitoring")
            return KubernetesCollector()
        
        # Fall back to Docker (always works)
        log.info("✓ Using Docker collector - cross-platform mode")
        return DockerEventCollector()
    
    @staticmethod
    async def _create_specific(collector_type: str) -> Optional[BaseEventCollector]:
        """Create a specific collector type."""
        if collector_type.lower() == 'falco':
            if await FalcoCollector.is_available():
                return FalcoCollector()
        
        elif collector_type.lower() == 'kubernetes':
            if await KubernetesCollector.is_available():
                return KubernetesCollector()
        
        elif collector_type.lower() == 'docker':
            return DockerEventCollector()
        
        return None
    
    @staticmethod
    async def get_available_collectors() -> dict:
        """Get status of all collectors."""
        return {
            "falco": await FalcoCollector.is_available(),
            "kubernetes": await KubernetesCollector.is_available(),
            "docker": True  # Docker always available (we assume)
        }