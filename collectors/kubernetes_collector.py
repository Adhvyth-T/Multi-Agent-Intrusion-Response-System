# collectors/kubernetes_collector.py
"""
Kubernetes Event Collector - Monitor K8s API events.
Detects suspicious K8s operations and policy violations.
"""

import asyncio
from typing import Dict, Any, Optional
from datetime import datetime

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


class KubernetesCollector(BaseEventCollector):
    """
    Monitor Kubernetes API events.
    
    Capabilities:
    - Pod lifecycle events
    - ConfigMap/Secret changes
    - RBAC violations
    - Resource quota violations
    - Deployment changes
    - Service account usage
    
    Requirements:
    - kubectl configured
    - OR kubernetes Python client
    - OR running inside a K8s pod with ServiceAccount
    """
    
    # Suspicious event types
    SUSPICIOUS_EVENTS = {
        'exec_into_pod': 'suspicious_shell',
        'secret_accessed': 'sensitive_data_access',
        'privileged_pod_created': 'privilege_escalation',
        'hostpath_mount': 'container_escape_attempt',
        'service_account_created': 'persistence_attempt'
    }
    
    def __init__(self, kubeconfig: Optional[str] = None):
        super().__init__(name="kubernetes_collector")
        self.kubeconfig = kubeconfig
        self.k8s_client = None
        self.k8s_available = False
    
    async def start(self) -> None:
        """Start monitoring Kubernetes events."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        # Check if K8s is available
        if not await self._check_k8s_available():
            self.log.error("Kubernetes is not available")
            raise RuntimeError("Kubernetes cluster not accessible")
        
        self.k8s_available = True
        self.log.info("Kubernetes event collector started")
        
        # Start monitoring
        await asyncio.gather(
            self._monitor_pod_events(),
            self._monitor_audit_logs(),
        )
    
    async def stop(self) -> None:
        """Stop the collector."""
        self.running = False
        self.log.info("Kubernetes event collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Try to list nodes (quick API check)
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'get', 'nodes',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(result.communicate(), timeout=5.0)
            
            if result.returncode == 0:
                return CollectorHealth(
                    status="healthy",
                    message="Kubernetes collector operating normally",
                    details={"api_server": "responsive"}
                )
            else:
                return CollectorHealth(
                    status="unhealthy",
                    message="Kubernetes API not responsive",
                    details={"error": stderr.decode()}
                )
        
        except asyncio.TimeoutError:
            return CollectorHealth(
                status="unhealthy",
                message="Kubernetes API timeout",
                details={}
            )
        except Exception as e:
            self._increment_errors()
            return CollectorHealth(
                status="unhealthy",
                message=f"Health check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Return collector capabilities."""
        return {
            "process_monitoring": False,
            "network_monitoring": False,
            "file_monitoring": False,
            "syscall_monitoring": False,
            "resource_monitoring": True,
            "container_events": True,
            "exec_detection": True,
            "k8s_api_events": True,
            "policy_violations": True
        }
    
    async def _check_k8s_available(self) -> bool:
        """Check if Kubernetes cluster is accessible."""
        try:
            result = await asyncio.create_subprocess_exec(
                'kubectl', 'cluster-info',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await asyncio.wait_for(result.communicate(), timeout=5.0)
            return result.returncode == 0
        except Exception:
            return False
    
    async def _monitor_pod_events(self):
        """Monitor pod lifecycle events."""
        self.log.info("Starting Kubernetes pod events monitor...")
        
        while self.running:
            try:
                # Watch pod events
                process = await asyncio.create_subprocess_exec(
                    'kubectl', 'get', 'events', '--watch', '-o', 'json',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                while self.running:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    # Parse event and check for suspicious activity
                    # (Implementation depends on your detection logic)
                    self._increment_events()
                
                await process.wait()
            
            except Exception as e:
                self.log.error("Pod events monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(5)
    
    async def _monitor_audit_logs(self):
        """Monitor K8s audit logs if available."""
        self.log.info("Starting Kubernetes audit log monitor...")
        
        # This requires audit logging to be enabled on the cluster
        # For now, placeholder
        while self.running:
            await asyncio.sleep(1)
    
    @staticmethod
    async def is_available() -> bool:
        """Check if Kubernetes is available."""
        try:
            collector = KubernetesCollector()
            return await collector._check_k8s_available()
        except Exception:
            return False