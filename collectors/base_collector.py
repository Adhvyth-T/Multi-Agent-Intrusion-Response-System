# collectors/base_collector.py
"""
Abstract base class for all event collectors.
Defines the interface that all collectors must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime
import structlog

log = structlog.get_logger()


@dataclass
class CollectorMetrics:
    """Metrics collected by a collector."""
    events_processed: int = 0
    threats_detected: int = 0
    errors: int = 0
    uptime_seconds: float = 0.0
    last_event_time: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "events_processed": self.events_processed,
            "threats_detected": self.threats_detected,
            "errors": self.errors,
            "uptime_seconds": self.uptime_seconds,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None
        }


@dataclass
class CollectorHealth:
    """Health status of a collector."""
    status: str  # "healthy", "degraded", "unhealthy"
    message: str
    details: Dict[str, Any]
    
    def is_healthy(self) -> bool:
        return self.status == "healthy"


class BaseEventCollector(ABC):
    """
    Abstract base class for all event collectors.
    
    Collectors are responsible for:
    1. Monitoring their respective data sources
    2. Detecting security events
    3. Normalizing events to a standard format
    4. Pushing events to the detection queue
    """
    
    def __init__(self, name: str):
        self.name = name
        self.running = False
        self.metrics = CollectorMetrics()
        self.start_time: Optional[datetime] = None
        self.log = structlog.get_logger().bind(collector=name)
    
    @abstractmethod
    async def start(self) -> None:
        """
        Start the collector.
        Should begin monitoring and continue until stop() is called.
        """
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """
        Stop the collector gracefully.
        Should cleanup resources and stop all monitoring tasks.
        """
        pass
    
    @abstractmethod
    async def health_check(self) -> CollectorHealth:
        """
        Check if the collector is healthy and functioning.
        
        Returns:
            CollectorHealth object with status and details
        """
        pass
    
    @abstractmethod
    def get_capabilities(self) -> Dict[str, bool]:
        """
        Return what this collector can detect.
        
        Returns:
            Dict of capability_name -> supported (bool)
            
        Example:
            {
                "process_monitoring": True,
                "network_monitoring": True,
                "file_monitoring": False,
                "syscall_monitoring": False
            }
        """
        pass
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current collector metrics.
        
        Returns:
            Dict of metric_name -> value
        """
        if self.start_time:
            self.metrics.uptime_seconds = (datetime.utcnow() - self.start_time).total_seconds()
        
        return {
            "name": self.name,
            "running": self.running,
            **self.metrics.to_dict()
        }
    
    def _normalize_event(self, raw_event: Dict[str, Any], threat_type: str, 
                        severity: str, evidence: str) -> Dict[str, Any]:
        """
        Normalize a raw event into the standard incident format.
        
        Args:
            raw_event: Original event data from the collector
            threat_type: Type of threat detected
            severity: Severity level (P1-P4)
            evidence: Evidence string explaining the detection
            
        Returns:
            Normalized event dict ready for the detection queue
        """
        return {
            "source": self.name,
            "type": threat_type,
            "resource": raw_event.get("resource", "unknown"),
            "namespace": raw_event.get("namespace", "default"),
            "timestamp": datetime.utcnow().isoformat(),
            "severity": severity,
            "details": {
                "threat_type": threat_type,
                "evidence": evidence,
                "detection_method": self.name,
                **raw_event.get("details", {})
            },
            "raw": raw_event
        }
    
    def _increment_events(self):
        """Increment event counter."""
        self.metrics.events_processed += 1
        self.metrics.last_event_time = datetime.utcnow()
    
    def _increment_threats(self):
        """Increment threat counter."""
        self.metrics.threats_detected += 1
    
    def _increment_errors(self):
        """Increment error counter."""
        self.metrics.errors += 1