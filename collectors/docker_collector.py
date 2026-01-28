# collectors/docker_collector.py
"""
Docker Event Collector - Cross-platform monitoring using Docker API.
Works on Windows, WSL2, Linux, Mac.
"""

import asyncio
import subprocess
import json
import re
from datetime import datetime
from typing import Dict, Any, Optional

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


class DockerEventCollector(BaseEventCollector):
    """
    Monitor Docker containers directly without Falco.
    
    Capabilities:
    - Process monitoring (docker top, ps aux)
    - Resource monitoring (CPU, memory)
    - Container lifecycle events
    - Exec command detection
    
    Limitations:
    - No syscall-level monitoring
    - No file integrity monitoring
    - Container-level visibility only
    """
    
    # Threat detection patterns
    THREAT_PATTERNS = {
        'cryptominer': [
            r'xmrig', r'minerd', r'cpuminer', r'ethminer', r'ccminer',
            r'stratum\+tcp', r'pool\.minexmr', r'cryptonight', r'monero'
        ],
        'reverse_shell': [
            r'/dev/tcp/', r'bash -i', r'sh -i', r'nc -e', r'ncat -e',
            r'netcat.*-e', r'socat', r'/bin/bash.*>&'
        ],
        'cpu_bomb': [
            r'while true', r':\(\)\{', r'stress', r'stress-ng'
        ],
        'port_scan': [
            r'nmap', r'masscan', r'zmap', r'unicornscan',
            r'for port in', r'nc -zv'
        ],
        'privilege_escalation': [
            r'sudo', r'su\s', r'pkexec', r'chmod \+s', r'setuid'
        ]
    }
    
    # Map internal threat types to normalized types
    THREAT_TYPE_MAP = {
        'cryptominer': 'cryptominer_detected',
        'reverse_shell': 'reverse_shell',
        'cpu_bomb': 'anomalous_cpu',
        'port_scan': 'suspicious_port_scan',
        'privilege_escalation': 'privilege_escalation',
        'anomalous_cpu': 'anomalous_cpu'
    }
    
    def __init__(self):
        super().__init__(name="docker_collector")
        self.monitored_containers = set()
        self.monitoring_tasks = []
        self.docker_available = False
    
    async def start(self) -> None:
        """Start monitoring Docker."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        # Check if Docker is available
        if not await self._check_docker_available():
            self.log.error("Docker is not available")
            raise RuntimeError("Docker daemon not accessible")
        
        self.docker_available = True
        self.log.info("Docker event collector started (cross-platform mode)")
        
        # Start all monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._monitor_docker_events()),
            asyncio.create_task(self._monitor_container_processes()),
            asyncio.create_task(self._monitor_container_stats()),
        ]
        
        # Wait for all tasks
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def stop(self) -> None:
        """Stop the collector."""
        self.running = False
        
        # Cancel all monitoring tasks
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        # Wait for cancellation
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.log.info("Docker event collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        # Check if Docker daemon is responsive
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Quick Docker ping
            result = subprocess.run(
                ['docker', 'info'],
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Check if we're still processing events
                if self.metrics.last_event_time:
                    time_since_last = (datetime.utcnow() - self.metrics.last_event_time).seconds
                    if time_since_last > 120:  # No events for 2 minutes
                        return CollectorHealth(
                            status="degraded",
                            message="No events received recently",
                            details={"seconds_since_last_event": time_since_last}
                        )
                
                return CollectorHealth(
                    status="healthy",
                    message="Docker collector operating normally",
                    details={
                        "containers_monitored": len(self.monitored_containers),
                        "docker_daemon": "responsive"
                    }
                )
            else:
                return CollectorHealth(
                    status="unhealthy",
                    message="Docker daemon not responsive",
                    details={"error": result.stderr.decode()}
                )
        
        except subprocess.TimeoutExpired:
            return CollectorHealth(
                status="unhealthy",
                message="Docker daemon timeout",
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
            "process_monitoring": True,
            "network_monitoring": False,  # Could be added
            "file_monitoring": False,
            "syscall_monitoring": False,
            "resource_monitoring": True,
            "container_events": True,
            "exec_detection": True
        }
    
    async def _check_docker_available(self) -> bool:
        """Check if Docker daemon is accessible."""
        try:
            result = subprocess.run(
                ['docker', 'version'],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _monitor_docker_events(self):
        """Monitor Docker daemon events."""
        self.log.info("Starting Docker events monitor...")
        
        while self.running:
            try:
                # Start docker events command
                process = await asyncio.create_subprocess_exec(
                    'docker', 'events', '--format', '{{json .}}',
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                # Read events line by line
                while self.running:
                    line = await process.stdout.readline()
                    if not line:
                        break
                    
                    try:
                        event = json.loads(line.decode().strip())
                        self._increment_events()
                        await self._process_docker_event(event)
                    except json.JSONDecodeError:
                        self._increment_errors()
                        continue
                
                await process.wait()
                
            except Exception as e:
                self.log.error("Docker events monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(5)
    
    async def _process_docker_event(self, event: Dict[str, Any]):
        """Process a Docker event."""
        try:
            event_type = event.get('Type')
            action = event.get('Action')
            
            if event_type == 'container':
                container_name = event.get('Actor', {}).get('Attributes', {}).get('name', '')
                
                # Track containers
                if action == 'start':
                    self.monitored_containers.add(container_name)
                    self.log.debug("Container started", container=container_name)
                
                elif action == 'die':
                    self.monitored_containers.discard(container_name)
                    self.log.debug("Container stopped", container=container_name)
                
                # Detect exec commands
                elif action in ['exec_create', 'exec_start']:
                    await self._inspect_exec(container_name)
        
        except Exception as e:
            self.log.error("Error processing Docker event", error=str(e))
            self._increment_errors()
    
    async def _inspect_exec(self, container_name: str):
        """Inspect exec command details."""
        try:
            result = subprocess.run(
                ['docker', 'exec', container_name, 'ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                threat = self._detect_threat_in_output(result.stdout)
                
                if threat:
                    await self._create_alert(
                        container=container_name,
                        threat_type=threat['type'],
                        evidence=threat['evidence'],
                        severity='P1' if threat['type'] in ['cryptominer', 'reverse_shell'] else 'P2'
                    )
        
        except Exception as e:
            self.log.debug("Exec inspection failed", container=container_name, error=str(e))
    
    async def _monitor_container_processes(self):
        """Periodically check processes in all containers."""
        self.log.info("Starting container process monitor...")
        
        while self.running:
            try:
                result = subprocess.run(
                    ['docker', 'ps', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    containers = result.stdout.strip().split('\n')
                    
                    for container in containers:
                        if not container:
                            continue
                        
                        await self._check_container_processes(container)
                
                await asyncio.sleep(10)  # Check every 10 seconds
            
            except Exception as e:
                self.log.error("Process monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(10)
    
    async def _check_container_processes(self, container: str):
        """Check processes in a specific container."""
        try:
            result = subprocess.run(
                ['docker', 'top', container],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                threat = self._detect_threat_in_output(result.stdout)
                
                if threat:
                    await self._create_alert(
                        container=container,
                        threat_type=threat['type'],
                        evidence=threat['evidence'],
                        severity='P1' if threat['type'] in ['cryptominer', 'reverse_shell'] else 'P2'
                    )
        
        except subprocess.TimeoutExpired:
            pass
        except Exception as e:
            self.log.debug("Process check failed", container=container, error=str(e))
    
    async def _monitor_container_stats(self):
        """Monitor container resource usage."""
        self.log.info("Starting container stats monitor...")
        
        while self.running:
            try:
                result = subprocess.run(
                    ['docker', 'stats', '--no-stream', '--format', 
                     '{{.Name}}\t{{.CPUPerc}}\t{{.MemPerc}}'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode == 0:
                    for line in result.stdout.strip().split('\n'):
                        if not line:
                            continue
                        
                        parts = line.split('\t')
                        if len(parts) >= 2:
                            container = parts[0]
                            cpu_str = parts[1].replace('%', '')
                            
                            try:
                                cpu = float(cpu_str)
                                
                                # Alert on high CPU (> 80%)
                                if cpu > 80.0:
                                    await self._create_alert(
                                        container=container,
                                        threat_type='anomalous_cpu',
                                        evidence=f'High CPU usage: {cpu:.1f}%',
                                        severity='P2'
                                    )
                            except ValueError:
                                pass
                
                await asyncio.sleep(15)  # Check every 15 seconds
            
            except Exception as e:
                self.log.error("Stats monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(15)
    
    def _detect_threat_in_output(self, output: str) -> Optional[Dict[str, str]]:
        """Detect threats in command/process output."""
        output_lower = output.lower()
        
        for threat_type, patterns in self.THREAT_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, output_lower, re.IGNORECASE):
                    return {
                        'type': threat_type,
                        'evidence': f'Pattern matched: {pattern}'
                    }
        
        return None
    
    async def _create_alert(self, container: str, threat_type: str, 
                           evidence: str, severity: str):
        """Create and queue a security alert."""
        
        normalized_event = self._normalize_event(
            raw_event={
                "resource": f"container/{container}",
                "namespace": "docker",
                "details": {
                    "container_name": container,
                    "threat_type": threat_type,
                    "evidence": evidence
                }
            },
            threat_type=self.THREAT_TYPE_MAP.get(threat_type, 'suspicious_activity'),
            severity=severity,
            evidence=evidence
        )
        
        await queue.push("detection", normalized_event)
        self._increment_threats()
        
        self.log.info("Threat detected",
                     container=container,
                     threat=threat_type,
                     evidence=evidence)