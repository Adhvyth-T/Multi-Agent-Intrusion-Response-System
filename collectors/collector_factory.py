# collectors/collector_factory.py
"""
Collector factory - Auto-detects and creates the best collectors for the environment.
Supports multiple simultaneous collectors for comprehensive monitoring.
"""

import structlog
from typing import List, Optional, Dict, Any
import os

from collectors.base_collector import BaseEventCollector
from collectors.docker_collector import DockerEventCollector
from collectors.kubernetes_collector import KubernetesCollector
from collectors.log_collector import LogCollector
from collectors.network_collector import NetworkCollector
from collectors.host_collector import HostCollector
from collectors.forensic_collector import ForensicCollector

# Import FalcoCollector if available (for Linux environments)
try:
    from collectors.falco_collector import FalcoCollector
    FALCO_AVAILABLE = True
except ImportError:
    FALCO_AVAILABLE = False
    
    class FalcoCollector:
        @staticmethod
        async def is_available():
            return False

log = structlog.get_logger()


class CollectorFactory:
    """
    Factory for creating appropriate collectors based on environment and requirements.
    
    Supports multiple collection strategies:
    1. Primary Security Collector (Falco > Docker > K8s)
    2. Investigation Collectors (Log, Network, Host, Forensic)
    3. Specialized collectors based on use case
    """
    
    @staticmethod
    async def create_security_collector(
        preferred: Optional[str] = None,
        fallback: bool = True
    ) -> BaseEventCollector:
        """
        Create the primary security event collector.
        
        Args:
            preferred: Force specific collector ('falco', 'kubernetes', 'docker')
            fallback: If preferred unavailable, fall back to next best
            
        Returns:
            BaseEventCollector instance
        """
        # Check for environment variable override
        env_collector = os.getenv('IR_SECURITY_COLLECTOR')
        if env_collector:
            preferred = env_collector
            log.info(f"Security collector preference from environment: {preferred}")
        
        # If specific collector requested
        if preferred:
            collector = await CollectorFactory._create_specific_security(preferred)
            if collector:
                return collector
            elif not fallback:
                raise RuntimeError(f"Requested security collector '{preferred}' not available")
            else:
                log.warning(f"Requested security collector '{preferred}' not available, trying fallback")
        
        # Auto-detect best security collector
        log.info("Auto-detecting best security collector...")
        
        # Try Falco first (production mode)
        if FALCO_AVAILABLE and await FalcoCollector.is_available():
            log.info("✓ Falco available - using production security monitoring")
            return FalcoCollector()
        
        # Try Kubernetes (if in cluster)
        if await KubernetesCollector.is_available():
            log.info("✓ Kubernetes available - using K8s API security monitoring")
            return KubernetesCollector()
        
        # Fall back to Docker (always works)
        log.info("✓ Using Docker collector - cross-platform security monitoring")
        return DockerEventCollector()
    
    @staticmethod
    async def create_investigation_collectors(
        collectors: Optional[List[str]] = None,
        evidence_dir: Optional[str] = None
    ) -> List[BaseEventCollector]:
        """
        Create collectors for Investigation Agent.
        
        Args:
            collectors: List of specific collectors to create
                       ['log', 'network', 'host', 'forensic'] or None for all
            evidence_dir: Directory for forensic evidence collection
            
        Returns:
            List of collectors ready for Investigation Agent
        """
        log.info("Creating investigation collectors", requested=collectors)
        
        available_collectors = {
            'log': LogCollector,
            'network': NetworkCollector, 
            'host': HostCollector,
            'forensic': ForensicCollector
        }
        
        if collectors is None:
            # Create all investigation collectors by default
            collectors = list(available_collectors.keys())
        
        created_collectors = []
        
        for collector_name in collectors:
            if collector_name not in available_collectors:
                log.warning(f"Unknown investigation collector: {collector_name}")
                continue
            
            try:
                collector_class = available_collectors[collector_name]
                
                # Special handling for collectors that need parameters
                if collector_name == 'forensic':
                    collector = collector_class(evidence_dir=evidence_dir)
                else:
                    collector = collector_class()
                
                created_collectors.append(collector)
                log.info(f"✓ Created {collector_name} collector")
            
            except Exception as e:
                log.error(f"Failed to create {collector_name} collector", error=str(e))
        
        log.info("Investigation collectors created", count=len(created_collectors))
        return created_collectors
    
    @staticmethod
    async def create_all_collectors(
        security_preferred: Optional[str] = None,
        investigation_collectors: Optional[List[str]] = None,
        evidence_dir: Optional[str] = None
    ) -> Dict[str, BaseEventCollector]:
        """
        Create complete collector suite for autonomous IR system.
        
        Returns:
            Dict mapping collector purpose to collector instance
        """
        log.info("Creating complete collector suite")
        
        collectors = {}
        
        # Primary security collector
        try:
            security_collector = await CollectorFactory.create_security_collector(
                preferred=security_preferred
            )
            collectors['security'] = security_collector
        except Exception as e:
            log.error("Failed to create security collector", error=str(e))
            raise RuntimeError("No security collector available")
        
        # Investigation collectors
        try:
            investigation_collectors_list = await CollectorFactory.create_investigation_collectors(
                collectors=investigation_collectors,
                evidence_dir=evidence_dir
            )
            
            for collector in investigation_collectors_list:
                collectors[collector.name] = collector
        
        except Exception as e:
            log.error("Failed to create investigation collectors", error=str(e))
        
        log.info("Complete collector suite created", 
                 total=len(collectors),
                 types=list(collectors.keys()))
        
        return collectors
    
    @staticmethod
    async def _create_specific_security(collector_type: str) -> Optional[BaseEventCollector]:
        """Create a specific security collector type."""
        if collector_type.lower() == 'falco' and FALCO_AVAILABLE:
            if await FalcoCollector.is_available():
                return FalcoCollector()
        
        elif collector_type.lower() == 'kubernetes':
            if await KubernetesCollector.is_available():
                return KubernetesCollector()
        
        elif collector_type.lower() == 'docker':
            return DockerEventCollector()
        
        return None
    
    @staticmethod
    async def get_available_collectors() -> Dict[str, Any]:
        """Get status of all collector types."""
        availability = {
            "security_collectors": {
                "falco": FALCO_AVAILABLE and await FalcoCollector.is_available(),
                "kubernetes": await KubernetesCollector.is_available(),
                "docker": True  # Docker always available (we assume)
            },
            "investigation_collectors": {
                "log": True,  # Log collector always available
                "network": True,  # Network collector always available
                "host": True,  # Host collector always available  
                "forensic": True  # Forensic collector always available
            }
        }
        
        return availability
    
    @staticmethod
    async def get_recommended_setup() -> Dict[str, Any]:
        """Get recommended collector setup for current environment."""
        availability = await CollectorFactory.get_available_collectors()
        
        # Recommend primary security collector
        if availability["security_collectors"]["falco"]:
            primary_security = "falco"
            reason = "Production-grade syscall monitoring with Falco"
        elif availability["security_collectors"]["kubernetes"]:
            primary_security = "kubernetes"
            reason = "Running in Kubernetes cluster - use K8s API monitoring"
        else:
            primary_security = "docker"
            reason = "Cross-platform Docker API monitoring"
        
        # Always recommend all investigation collectors
        investigation = list(availability["investigation_collectors"].keys())
        
        return {
            "primary_security": {
                "collector": primary_security,
                "reason": reason
            },
            "investigation_collectors": investigation,
            "setup_command": {
                "security_collector": primary_security,
                "investigation_collectors": investigation
            },
            "capabilities": {
                "real_time_detection": availability["security_collectors"][primary_security],
                "forensic_analysis": True,
                "log_analysis": True,
                "network_monitoring": True,
                "host_monitoring": True
            }
        }


class CollectorManager:
    """
    Manages multiple collectors for the IR system.
    """
    
    def __init__(self):
        self.collectors: Dict[str, BaseEventCollector] = {}
        self.running = False
    
    async def add_collector(self, name: str, collector: BaseEventCollector):
        """Add a collector to the manager."""
        self.collectors[name] = collector
        
        if self.running:
            # Start immediately if manager is already running
            try:
                await collector.start()
                log.info(f"Started collector: {name}")
            except Exception as e:
                log.error(f"Failed to start collector {name}", error=str(e))
    
    async def start_all(self):
        """Start all managed collectors."""
        self.running = True
        
        log.info("Starting all collectors", count=len(self.collectors))
        
        start_tasks = []
        for name, collector in self.collectors.items():
            start_tasks.append(self._start_collector(name, collector))
        
        # Start all collectors concurrently
        results = await asyncio.gather(*start_tasks, return_exceptions=True)
        
        # Check results
        failed_collectors = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                collector_name = list(self.collectors.keys())[i]
                failed_collectors.append(collector_name)
                log.error(f"Failed to start collector {collector_name}", error=str(result))
        
        if failed_collectors:
            log.warning("Some collectors failed to start", failed=failed_collectors)
        
        successful = len(self.collectors) - len(failed_collectors)
        log.info(f"Collectors started: {successful}/{len(self.collectors)}")
    
    async def _start_collector(self, name: str, collector: BaseEventCollector):
        """Start a single collector with error handling."""
        try:
            await collector.start()
            log.info(f"✓ Started {name} collector")
        except Exception as e:
            log.error(f"✗ Failed to start {name} collector", error=str(e))
            raise
    
    async def stop_all(self):
        """Stop all managed collectors."""
        self.running = False
        
        log.info("Stopping all collectors", count=len(self.collectors))
        
        stop_tasks = []
        for name, collector in self.collectors.items():
            stop_tasks.append(self._stop_collector(name, collector))
        
        # Stop all collectors concurrently
        await asyncio.gather(*stop_tasks, return_exceptions=True)
        
        log.info("All collectors stopped")
    
    async def _stop_collector(self, name: str, collector: BaseEventCollector):
        """Stop a single collector with error handling."""
        try:
            await collector.stop()
            log.info(f"✓ Stopped {name} collector")
        except Exception as e:
            log.error(f"✗ Error stopping {name} collector", error=str(e))
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of all collectors."""
        status = {}
        
        for name, collector in self.collectors.items():
            try:
                health = await collector.health_check()
                status[name] = {
                    "status": health.status,
                    "message": health.message,
                    "details": health.details,
                    "metrics": collector.get_metrics(),
                    "capabilities": collector.get_capabilities()
                }
            except Exception as e:
                status[name] = {
                    "status": "error",
                    "message": f"Health check failed: {str(e)}",
                    "details": {},
                    "metrics": {},
                    "capabilities": {}
                }
        
        return status
    
    def get_collector(self, name: str) -> Optional[BaseEventCollector]:
        """Get a specific collector by name."""
        return self.collectors.get(name)
    
    def list_collectors(self) -> List[str]:
        """List names of all managed collectors."""
        return list(self.collectors.keys())

# Need to import asyncio for CollectorManager
import asyncio