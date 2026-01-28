# agents/detection.py (COMPLETE WITH DEDUPLICATION)
"""
Detection Agent - Now using specialized ML models per attack type.
"""

import asyncio
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import structlog

from core import queue, save_incident, Incident, Severity
from ml_models import (
    CryptominerDetector,
    ExfiltrationDetector,
    PrivilegeDetector,
    ReverseShellDetector,
    ContainerEscapeDetector,
    NetworkAnomalyDetector
)

log = structlog.get_logger()

@dataclass
class DetectedEvent:
    """Normalized event from various sources."""
    source: str
    event_type: str
    resource: str
    namespace: str
    timestamp: datetime
    details: Dict[str, Any]
    raw: Dict[str, Any]


class IncidentDeduplicator:
    """
    Prevent duplicate incidents using fingerprinting + cooldown.
    Same container + same threat = same incident (don't re-create).
    """
    
    def __init__(self, cooldown_minutes: int = 5):
        self.active_incidents: Dict[str, Dict[str, Any]] = {}
        self.cooldown_minutes = cooldown_minutes
    
    def get_fingerprint(self, resource: str, threat_type: str, namespace: str) -> str:
        """
        Create unique fingerprint for an incident.
        
        Examples:
        - container/nginx + cryptominer + docker = "abc123def456"
        - container/redis + privilege_escalation + docker = "xyz789abc123"
        """
        key = f"{resource}|{threat_type}|{namespace}"
        fingerprint = hashlib.md5(key.encode()).hexdigest()[:12]
        return fingerprint
    
    def is_duplicate(self, resource: str, threat_type: str, namespace: str) -> tuple[bool, Optional[str]]:
        """
        Check if this incident was recently created.
        
        Returns:
            (is_duplicate, existing_incident_id)
        """
        fingerprint = self.get_fingerprint(resource, threat_type, namespace)
        
        # Check if we have an active incident with this fingerprint
        if fingerprint in self.active_incidents:
            incident_data = self.active_incidents[fingerprint]
            last_seen = incident_data['last_seen']
            incident_id = incident_data['incident_id']
            
            time_since = datetime.utcnow() - last_seen
            
            if time_since < timedelta(minutes=self.cooldown_minutes):
                # Still in cooldown period - this is a duplicate
                log.debug(
                    "Duplicate incident suppressed",
                    fingerprint=fingerprint,
                    incident_id=incident_id,
                    time_since_seconds=int(time_since.total_seconds()),
                    cooldown_seconds=self.cooldown_minutes * 60
                )
                
                # Update last_seen to extend the cooldown
                self.active_incidents[fingerprint]['last_seen'] = datetime.utcnow()
                self.active_incidents[fingerprint]['detection_count'] += 1
                
                return True, incident_id
        
        # Not a duplicate - return False
        return False, None
    
    def register_incident(self, resource: str, threat_type: str, namespace: str, incident_id: str):
        """Register a new incident to track for deduplication."""
        fingerprint = self.get_fingerprint(resource, threat_type, namespace)
        
        self.active_incidents[fingerprint] = {
            'incident_id': incident_id,
            'resource': resource,
            'threat_type': threat_type,
            'namespace': namespace,
            'first_seen': datetime.utcnow(),
            'last_seen': datetime.utcnow(),
            'detection_count': 1
        }
        
        log.debug(
            "Incident registered for deduplication",
            fingerprint=fingerprint,
            incident_id=incident_id
        )
        
        # Clean up old entries
        self._cleanup_old_incidents()
    
    def _cleanup_old_incidents(self):
        """Remove incidents older than 2x cooldown period."""
        cutoff = datetime.utcnow() - timedelta(minutes=self.cooldown_minutes * 2)
        
        to_remove = [
            fp for fp, data in self.active_incidents.items()
            if data['last_seen'] < cutoff
        ]
        
        for fp in to_remove:
            data = self.active_incidents[fp]
            log.debug(
                "Incident fingerprint expired",
                fingerprint=fp,
                incident_id=data['incident_id'],
                detection_count=data['detection_count']
            )
            del self.active_incidents[fp]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        return {
            'active_incidents': len(self.active_incidents),
            'cooldown_minutes': self.cooldown_minutes,
            'incidents': [
                {
                    'fingerprint': fp[:8],
                    'incident_id': data['incident_id'],
                    'resource': data['resource'],
                    'threat_type': data['threat_type'],
                    'detection_count': data['detection_count'],
                    'age_seconds': int((datetime.utcnow() - data['first_seen']).total_seconds())
                }
                for fp, data in self.active_incidents.items()
            ]
        }


class MultiModelDetector:
    """Ensemble of specialized ML models for different attack types."""
    
    def __init__(self):
        log.info("Initializing ML detection models...")
        self.cryptominer = CryptominerDetector()
        self.exfiltration = ExfiltrationDetector()
        self.privilege = PrivilegeDetector()
        self.shell = ReverseShellDetector()
        self.escape = ContainerEscapeDetector()
        self.network = NetworkAnomalyDetector()
        
        log.info("ML models loaded", 
                 trained=[
                     f"cryptominer: {self.cryptominer.trained}",
                     f"exfiltration: {self.exfiltration.trained}",
                     f"privilege: {self.privilege.trained}",
                     f"shell: {self.shell.trained}",
                     f"network: {self.network.trained}"
                 ])
    
    def detect(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Run all models and return best match."""
        results = []
        
        # Run each specialized detector
        detectors = [
            ('cryptominer', self.cryptominer, Severity.P1),
            ('data_exfiltration', self.exfiltration, Severity.P1),
            ('privilege_escalation', self.privilege, Severity.P1),
            ('reverse_shell', self.shell, Severity.P1),
            ('container_escape', self.escape, Severity.P1),
            ('suspicious_process', self.network, Severity.P2)
        ]
        
        for threat_type, detector, severity in detectors:
            is_threat, confidence = detector.predict(event)
            if is_threat:
                results.append({
                    'threat_type': threat_type,
                    'severity': severity,
                    'confidence': confidence,
                    'detector': detector.model_name
                })
        
        # Return highest confidence detection
        if results:
            best = max(results, key=lambda x: x['confidence'])
            return best
        
        return None


class DetectionAgent:
    """Main detection agent using specialized ML models."""
    
    def __init__(self, dedup_cooldown_minutes: int = 5):
        self.detector = MultiModelDetector()
        self.deduplicator = IncidentDeduplicator(cooldown_minutes=dedup_cooldown_minutes)
        self.running = False
        
        log.info(
            "Detection Agent initialized",
            deduplication_cooldown_minutes=dedup_cooldown_minutes
        )
    
    async def start(self):
        """Start the detection agent."""
        self.running = True
        log.info("Detection Agent started with ML models + deduplication")
        await self._event_loop()
    
    async def stop(self):
        """Stop the detection agent."""
        self.running = False
        log.info("Detection Agent stopped")
    
    async def _event_loop(self):
        """Main event processing loop."""
        while self.running:
            try:
                event_data = await queue.pop("detection", timeout=5)
                
                if event_data:
                    event = self._normalize_event(event_data)
                    await self._process_event(event)
            except Exception as e:
                log.error("Error processing event", error=str(e))
                await asyncio.sleep(1)
    
    def _normalize_event(self, raw_event: Dict[str, Any]) -> DetectedEvent:
        """Normalize raw event into standard format."""
        return DetectedEvent(
            source=raw_event.get("source", "unknown"),
            event_type=raw_event.get("type", "unknown"),
            resource=raw_event.get("resource", "unknown"),
            namespace=raw_event.get("namespace", "default"),
            timestamp=datetime.fromisoformat(raw_event.get("timestamp", datetime.utcnow().isoformat())),
            details=raw_event.get("details", {}),
            raw=raw_event
        )
    
    async def _process_event(self, event: DetectedEvent):
        """Process event through ML models."""
        log.info("Processing event", source=event.source, type=event.event_type)
        
        # Convert to dict for ML models
        event_dict = {
            'source': event.source,
            'type': event.event_type,
            'resource': event.resource,
            'namespace': event.namespace,
            'details': event.details,
            'raw': event.raw
        }
        
        # Run ML detection
        detection = self.detector.detect(event_dict)
        
        if detection:
            # Check for duplicates BEFORE creating incident
            is_duplicate, existing_id = self.deduplicator.is_duplicate(
                resource=event.resource,
                threat_type=detection['threat_type'],
                namespace=event.namespace
            )
            
            if is_duplicate:
                log.info(
                    "Duplicate detection ignored",
                    existing_incident_id=existing_id,
                    resource=event.resource,
                    threat_type=detection['threat_type']
                )
                return  # Skip creating new incident
            
            # NEW threat detected! Create incident
            incident = await self._create_incident(
                event,
                detection['threat_type'],
                detection['severity'],
                detection['confidence'],
                [f"ML Detection: {detection['detector']} (confidence: {detection['confidence']:.2f})"]
            )
            
            # Register for deduplication
            self.deduplicator.register_incident(
                resource=event.resource,
                threat_type=detection['threat_type'],
                namespace=event.namespace,
                incident_id=incident.id
            )
            
            # Push to triage queue
            await queue.push("triage", incident.model_dump(mode='json'))
            
            # Send notification
            await queue.push("notification", {
                "type": "incident_detected",
                "incident_id": incident.id,
                "severity": incident.severity.value,
                "threat_type": detection['threat_type'],
                "resource": incident.resource,
                "summary": f"ML Detection: {detection['threat_type']} (confidence: {detection['confidence']:.0%})"
            })
            
            log.info("New incident created",
                     incident_id=incident.id,
                     threat_type=detection['threat_type'],
                     confidence=detection['confidence'],
                     detector=detection['detector'])
    
    async def _create_incident(
        self,
        event: DetectedEvent,
        threat_type: str,
        severity: Severity,
        confidence: float,
        reasons: List[str]
    ) -> Incident:
        """Create and save incident from detected event."""
        
        incident = Incident(
            type=threat_type,
            severity=severity,
            source=event.source,
            resource=event.resource,
            namespace=event.namespace,
            raw_event={
                "event": event.raw,
                "detection_confidence": confidence,
                "detection_reasons": reasons,
                "ml_detection": True
            }
        )
        
        # Save to database
        await save_incident(incident.model_dump(mode='json'))
        
        return incident
    
    def get_dedup_stats(self) -> Dict[str, Any]:
        """Get deduplication statistics (for debugging/monitoring)."""
        return self.deduplicator.get_stats()


# Agent instance
detection_agent = DetectionAgent(dedup_cooldown_minutes=5)


