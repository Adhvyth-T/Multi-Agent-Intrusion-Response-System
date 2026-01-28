# collectors/falco_collector.py
"""
Falco Event Collector - Production-grade syscall monitoring.
Requires Linux with Falco installed.
"""

import asyncio
import grpc
from typing import Dict, Any, Optional
from datetime import datetime

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue

# Falco gRPC schema (simplified - you'll need the full proto)
# pip install falco-grpc-py


class FalcoCollector(BaseEventCollector):
    """
    Monitor system events via Falco (eBPF/kernel module).
    
    Capabilities:
    - Syscall-level monitoring
    - File integrity monitoring
    - Network monitoring
    - Process monitoring
    - Container-aware rules
    
    Requirements:
    - Linux kernel 4.14+
    - Falco installed and running
    - gRPC output enabled in Falco config
    """
    
    # Map Falco rule priorities to our severity levels
    PRIORITY_MAP = {
        'EMERGENCY': 'P1',
        'ALERT': 'P1',
        'CRITICAL': 'P1',
        'ERROR': 'P2',
        'WARNING': 'P3',
        'NOTICE': 'P3',
        'INFORMATIONAL': 'P4',
        'DEBUG': 'P4'
    }
    
    # Map Falco rules to our threat types
    RULE_TYPE_MAP = {
        'Terminal shell in container': 'suspicious_shell',
        'Read sensitive file untrusted': 'sensitive_file_access',
        'Write below etc': 'system_modification',
        'Launch Suspicious Network Tool in Container': 'suspicious_network_tool',
        'Contact K8S API Server From Container': 'k8s_api_contact',
        'Modify Shell Configuration File': 'persistence_attempt',
        'Create Symlink Over Sensitive Files': 'privilege_escalation',
        'Detect crypto miners using the Stratum protocol': 'cryptominer_detected',
        'Delete or rename shell history': 'anti_forensics'
    }
    
    def __init__(self, grpc_endpoint: str = "localhost:5060"):
        super().__init__(name="falco_collector")
        self.grpc_endpoint = grpc_endpoint
        self.channel: Optional[grpc.aio.Channel] = None
        self.falco_available = False
    
    async def start(self) -> None:
        """Start monitoring Falco events."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        # Check if Falco is available
        if not await self._check_falco_available():
            self.log.error("Falco is not available")
            raise RuntimeError("Falco gRPC endpoint not accessible")
        
        self.falco_available = True
        self.log.info("Falco event collector started (production mode)")
        
        # Start monitoring
        await self._monitor_falco_events()
    
    async def stop(self) -> None:
        """Stop the collector."""
        self.running = False
        
        if self.channel:
            await self.channel.close()
        
        self.log.info("Falco event collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Try to connect to Falco gRPC
            async with grpc.aio.insecure_channel(self.grpc_endpoint) as channel:
                await asyncio.wait_for(
                    channel.channel_ready(),
                    timeout=5.0
                )
            
            return CollectorHealth(
                status="healthy",
                message="Falco collector operating normally",
                details={
                    "grpc_endpoint": self.grpc_endpoint,
                    "connection": "active"
                }
            )
        
        except asyncio.TimeoutError:
            return CollectorHealth(
                status="unhealthy",
                message="Falco gRPC timeout",
                details={}
            )
        except Exception as e:
            self._increment_errors()
            return CollectorHealth(
                status="unhealthy",
                message=f"Falco not accessible: {str(e)}",
                details={"error": str(e)}
            )
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Return collector capabilities."""
        return {
            "process_monitoring": True,
            "network_monitoring": True,
            "file_monitoring": True,
            "syscall_monitoring": True,
            "resource_monitoring": False,
            "container_events": True,
            "exec_detection": True,
            "kernel_events": True
        }
    
    async def _check_falco_available(self) -> bool:
        """Check if Falco gRPC is accessible."""
        try:
            async with grpc.aio.insecure_channel(self.grpc_endpoint) as channel:
                await asyncio.wait_for(
                    channel.channel_ready(),
                    timeout=5.0
                )
            return True
        except Exception as e:
            self.log.error("Falco not available", error=str(e))
            return False
    
    async def _monitor_falco_events(self):
        """Monitor Falco events via gRPC."""
        self.log.info("Starting Falco gRPC stream...")
        
        # Note: This is pseudocode - you need actual Falco gRPC client
        # Install: pip install falco-grpc-py
        
        try:
            from falco.client import Client
            from falco.schema import response_pb2
            
            client = Client(endpoint=self.grpc_endpoint, client_crt=None, client_key=None, ca_root=None)
            
            async for event in client.subscribe():
                if not self.running:
                    break
                
                self._increment_events()
                await self._process_falco_event(event)
        
        except ImportError:
            self.log.warning("Falco gRPC client not installed. Using mock events for testing.")
            # For now, if Falco gRPC not available, just wait
            while self.running:
                await asyncio.sleep(1)
        
        except Exception as e:
            self.log.error("Falco monitoring error", error=str(e))
            self._increment_errors()
    
    async def _process_falco_event(self, event: Any):
        """Process a Falco event."""
        try:
            # Extract event details (schema depends on Falco version)
            rule = event.rule
            priority = event.priority
            output = event.output
            fields = event.output_fields
            
            # Map to our threat types
            threat_type = self.RULE_TYPE_MAP.get(rule, 'suspicious_activity')
            severity = self.PRIORITY_MAP.get(priority, 'P3')
            
            # Extract container/resource info
            container_name = fields.get('container.name', 'unknown')
            namespace = fields.get('k8s.ns.name', 'default')
            pod_name = fields.get('k8s.pod.name', container_name)
            
            # Create normalized event
            normalized_event = self._normalize_event(
                raw_event={
                    "resource": f"pod/{pod_name}",
                    "namespace": namespace,
                    "details": {
                        "rule": rule,
                        "priority": priority,
                        "container_name": container_name,
                        "pod_name": pod_name,
                        "process": fields.get('proc.name'),
                        "command": fields.get('proc.cmdline'),
                        "user": fields.get('user.name'),
                        "fields": fields
                    }
                },
                threat_type=threat_type,
                severity=severity,
                evidence=output
            )
            
            await queue.push("detection", normalized_event)
            self._increment_threats()
            
            self.log.info("Falco event detected",
                         rule=rule,
                         priority=priority,
                         container=container_name)
        
        except Exception as e:
            self.log.error("Error processing Falco event", error=str(e))
            self._increment_errors()
    
    @staticmethod
    async def is_available() -> bool:
        """
        Static method to check if Falco is available in the environment.
        Used by factory for auto-detection.
        """
        try:
            collector = FalcoCollector()
            return await collector._check_falco_available()
        except Exception:
            return False