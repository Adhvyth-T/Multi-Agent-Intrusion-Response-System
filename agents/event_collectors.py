# agents/event_collectors.py
"""
Event collector using Docker API directly (No Falco needed - Windows/WSL2 compatible).
"""

import asyncio
import subprocess
import json
import structlog
from datetime import datetime
from typing import Dict, Any, List
import re

from core import queue

log = structlog.get_logger()

class DockerEventCollector:
    """
    Monitor Docker containers directly without Falco.
    Works on Windows, WSL2, Linux, Mac.
    """
    
    def __init__(self):
        self.running = False
        self.monitored_containers = set()
        
        # Suspicious patterns to detect
        self.threat_patterns = {
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
    
    async def start(self):
        """Start monitoring Docker."""
        self.running = True
        log.info("Docker event collector started (No Falco - Direct monitoring)")
        
        # Run all monitoring tasks in parallel
        await asyncio.gather(
            self._monitor_docker_events(),
            self._monitor_container_processes(),
            self._monitor_container_stats(),
        )
    
    async def _monitor_docker_events(self):
        """Monitor Docker daemon events."""
        log.info("Starting Docker events monitor...")
        
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
                        await self._process_docker_event(event)
                    except json.JSONDecodeError:
                        continue
                
                await process.wait()
                
            except Exception as e:
                log.error("Docker events monitor error", error=str(e))
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
                    log.debug("Container started", container=container_name)
                
                elif action == 'die':
                    self.monitored_containers.discard(container_name)
                    log.debug("Container stopped", container=container_name)
                
                # Detect exec commands (someone running commands in container)
                elif action in ['exec_create', 'exec_start']:
                    exec_id = event.get('Actor', {}).get('Attributes', {}).get('execID', '')
                    
                    # Try to get exec details
                    await self._inspect_exec(container_name, exec_id)
        
        except Exception as e:
            log.error("Error processing Docker event", error=str(e))
    
    async def _inspect_exec(self, container_name: str, exec_id: str):
        """Inspect exec command details."""
        try:
            # Get exec details
            result = subprocess.run(
                ['docker', 'exec', container_name, 'ps', 'aux'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                processes = result.stdout
                threat = self._detect_threat_in_output(processes)
                
                if threat:
                    await self._create_alert(
                        container=container_name,
                        threat_type=threat['type'],
                        evidence=threat['evidence'],
                        severity='P1' if threat['type'] in ['cryptominer', 'reverse_shell'] else 'P2'
                    )
        
        except Exception as e:
            log.debug("Exec inspection failed", container=container_name, error=str(e))
    
    async def _monitor_container_processes(self):
        """Periodically check processes in all containers."""
        log.info("Starting container process monitor...")
        
        while self.running:
            try:
                # Get list of running containers
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
                log.error("Process monitor error", error=str(e))
                await asyncio.sleep(10)
    
    async def _check_container_processes(self, container: str):
        """Check processes running in a specific container."""
        try:
            # Get process list
            result = subprocess.run(
                ['docker', 'top', container],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                processes = result.stdout
                threat = self._detect_threat_in_output(processes)
                
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
            log.debug("Process check failed", container=container, error=str(e))
    
    async def _monitor_container_stats(self):
        """Monitor container resource usage."""
        log.info("Starting container stats monitor...")
        
        while self.running:
            try:
                # Get stats for all containers
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
                log.error("Stats monitor error", error=str(e))
                await asyncio.sleep(15)
    
    def _detect_threat_in_output(self, output: str) -> Dict[str, str]:
        """Detect threats in command/process output."""
        output_lower = output.lower()
        
        for threat_type, patterns in self.threat_patterns.items():
            for pattern in patterns:
                if re.search(pattern, output_lower, re.IGNORECASE):
                    return {
                        'type': threat_type,
                        'evidence': f'Pattern matched: {pattern}'
                    }
        
        return None
    
    async def _create_alert(self, container: str, threat_type: str, evidence: str, severity: str):
        """Create and queue a security alert."""
        
        # Map threat types
        threat_map = {
            'cryptominer': 'cryptominer_detected',
            'reverse_shell': 'reverse_shell',
            'cpu_bomb': 'anomalous_cpu',
            'port_scan': 'suspicious_port_scan',
            'privilege_escalation': 'privilege_escalation',
            'anomalous_cpu': 'anomalous_cpu'
        }
        
        normalized_event = {
            "source": "docker_monitor",
            "type": threat_map.get(threat_type, 'suspicious_activity'),
            "resource": f"container/{container}",
            "namespace": "docker",
            "timestamp": datetime.utcnow().isoformat(),
            "severity": severity,
            "details": {
                "container_name": container,
                "threat_type": threat_type,
                "evidence": evidence,
                "detection_method": "direct_monitoring"
            },
            "raw": {
                "threat_type": threat_type,
                "evidence": evidence
            }
        }
        
        await queue.push("detection", normalized_event)
        log.info("Threat detected",
                container=container,
                threat=threat_type,
                evidence=evidence)
    
    async def stop(self):
        """Stop the collector."""
        self.running = False
        log.info("Docker event collector stopped")


# Singleton instance
falco_collector = DockerEventCollector()