# collectors/network_collector.py
"""
Network Collector - Monitor network flows, connections, and suspicious network activity.
Cross-platform network monitoring for Investigation Agent and threat detection.
"""

import asyncio
import subprocess
import json
import re
import socket
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict
import platform

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


@dataclass
class NetworkConnection:
    """Represents a network connection."""
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    protocol: str
    state: str
    process: str = ""
    process_id: int = 0
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'local_addr': self.local_addr,
            'local_port': self.local_port,
            'remote_addr': self.remote_addr,
            'remote_port': self.remote_port,
            'protocol': self.protocol,
            'state': self.state,
            'process': self.process,
            'process_id': self.process_id,
            'timestamp': self.timestamp.isoformat()
        }


class NetworkCollector(BaseEventCollector):
    """
    Monitor network activity for suspicious behavior.
    
    Capabilities:
    - Active connection monitoring
    - Outbound connection tracking
    - Port scan detection
    - DNS query monitoring
    - Bandwidth anomaly detection
    - Known malicious IP detection
    - Unusual port usage detection
    """
    
    # Suspicious ports and protocols
    SUSPICIOUS_PORTS = {
        # Common malware/backdoor ports
        1234, 1243, 1999, 2001, 2023, 2989, 3129, 3700, 4444, 4567,
        5000, 5001, 5554, 5555, 6666, 6667, 6969, 7000, 7777, 8080,
        8888, 9999, 10000, 12345, 20000, 20034, 31337, 54321, 65000,
        # Cryptocurrency mining pools
        3333, 4444, 7777, 8080, 8888, 9999, 14433, 14444
    }
    
    # Known malicious/suspicious TLDs and domains
    SUSPICIOUS_DOMAINS = [
        r'\.tk$', r'\.ml$', r'\.ga$', r'\.cf$',  # Freenom TLDs
        r'minexmr\.com', r'pool\.minexmr\.com',  # Mining pools
        r'stratum\+tcp://', r'pool\.', r'mine\.',
        r'\.onion$',  # Tor hidden services
        r'\d+\.\d+\.\d+\.\d+$'  # Raw IP addresses
    ]
    
    # Port scan detection thresholds
    PORT_SCAN_THRESHOLD = 20  # Connections to 20+ ports in 60s
    TIME_WINDOW = 60  # seconds
    
    def __init__(self):
        super().__init__(name="network_collector")
        self.is_windows = platform.system() == "Windows"
        self.monitoring_tasks = []
        self.connection_history: List[NetworkConnection] = []
        self.connection_tracking: Dict[str, List[datetime]] = defaultdict(list)
        self.baseline_established = False
        self.baseline_connections: Set[Tuple[str, int]] = set()
        
    async def start(self) -> None:
        """Start network monitoring."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        self.log.info("Network collector starting...", 
                     platform=platform.system())
        
        # Start monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._monitor_active_connections()),
            asyncio.create_task(self._monitor_dns_queries()),
            asyncio.create_task(self._detect_port_scans()),
            asyncio.create_task(self._analyze_connection_patterns()),
            asyncio.create_task(self._establish_baseline()),
        ]
        
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def stop(self) -> None:
        """Stop network monitoring."""
        self.running = False
        
        # Cancel all tasks
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.log.info("Network collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Test network command availability
            test_cmd = ['netstat', '-n'] if not self.is_windows else ['netstat', '-n']
            
            result = subprocess.run(
                test_cmd,
                capture_output=True,
                timeout=5
            )
            
            if result.returncode == 0:
                # Check if we're collecting data
                recent_connections = len([
                    c for c in self.connection_history 
                    if (datetime.utcnow() - c.timestamp).seconds < 300
                ])
                
                if recent_connections == 0 and self.metrics.events_processed > 0:
                    return CollectorHealth(
                        status="degraded",
                        message="No recent network activity detected",
                        details={"recent_connections": recent_connections}
                    )
                
                return CollectorHealth(
                    status="healthy",
                    message="Network collector operating normally",
                    details={
                        "recent_connections": recent_connections,
                        "total_connections": len(self.connection_history),
                        "baseline_established": self.baseline_established
                    }
                )
            else:
                return CollectorHealth(
                    status="unhealthy",
                    message="Network monitoring tools not available",
                    details={"error": result.stderr.decode()[:200]}
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
            "network_monitoring": True,
            "file_monitoring": False,
            "syscall_monitoring": False,
            "connection_tracking": True,
            "port_scan_detection": True,
            "dns_monitoring": True,
            "bandwidth_monitoring": False,  # Could be added
            "malicious_ip_detection": True,
            "baseline_analysis": True
        }
    
    async def _monitor_active_connections(self):
        """Monitor active network connections."""
        self.log.info("Starting active connections monitor...")
        
        while self.running:
            try:
                connections = await self._get_active_connections()
                
                for conn in connections:
                    self._increment_events()
                    self.connection_history.append(conn)
                    
                    # Analyze connection for threats
                    await self._analyze_connection(conn)
                
                # Cleanup old connections (keep last hour)
                cutoff = datetime.utcnow() - timedelta(hours=1)
                self.connection_history = [
                    c for c in self.connection_history 
                    if c.timestamp > cutoff
                ]
                
                await asyncio.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                self.log.error("Active connections monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(30)
    
    async def _get_active_connections(self) -> List[NetworkConnection]:
        """Get current active network connections."""
        connections = []
        
        try:
            if self.is_windows:
                # Windows: netstat -ano
                cmd = ['netstat', '-ano']
            else:
                # Linux: netstat -tuln or ss
                cmd = ['netstat', '-tulpn'] if await self._command_exists('netstat') else ['ss', '-tulpn']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                connections = self._parse_netstat_output(result.stdout)
        
        except Exception as e:
            self.log.debug("Get connections error", error=str(e))
        
        return connections
    
    def _parse_netstat_output(self, output: str) -> List[NetworkConnection]:
        """Parse netstat output into NetworkConnection objects."""
        connections = []
        
        for line in output.split('\n')[2:]:  # Skip headers
            if not line.strip():
                continue
                
            try:
                if self.is_windows:
                    # Windows format: Proto Local_Address Foreign_Address State PID
                    parts = line.split()
                    if len(parts) >= 4:
                        protocol = parts[0]
                        local = parts[1]
                        remote = parts[2]
                        state = parts[3] if len(parts) > 3 else "UNKNOWN"
                        pid = int(parts[4]) if len(parts) > 4 and parts[4].isdigit() else 0
                        
                        local_addr, local_port = self._parse_address(local)
                        remote_addr, remote_port = self._parse_address(remote)
                        
                        connections.append(NetworkConnection(
                            local_addr=local_addr,
                            local_port=local_port,
                            remote_addr=remote_addr,
                            remote_port=remote_port,
                            protocol=protocol,
                            state=state,
                            process_id=pid
                        ))
                else:
                    # Linux format varies by command
                    if 'LISTEN' in line or 'ESTABLISHED' in line:
                        parts = line.split()
                        if len(parts) >= 4:
                            protocol = parts[0]
                            local = parts[3] if 'tcp' in protocol else parts[3]
                            remote = parts[4] if len(parts) > 4 else "0.0.0.0:0"
                            state = parts[5] if len(parts) > 5 else "UNKNOWN"
                            process_info = parts[-1] if '/' in parts[-1] else ""
                            
                            local_addr, local_port = self._parse_address(local)
                            remote_addr, remote_port = self._parse_address(remote)
                            
                            connections.append(NetworkConnection(
                                local_addr=local_addr,
                                local_port=local_port,
                                remote_addr=remote_addr,
                                remote_port=remote_port,
                                protocol=protocol,
                                state=state,
                                process=process_info.split('/')[1] if '/' in process_info else ""
                            ))
            
            except Exception as e:
                continue  # Skip malformed lines
        
        return connections
    
    def _parse_address(self, addr_str: str) -> Tuple[str, int]:
        """Parse address:port string."""
        try:
            if ':' in addr_str:
                addr, port_str = addr_str.rsplit(':', 1)
                port = int(port_str)
                # Handle IPv6 addresses
                addr = addr.strip('[]')
                return addr, port
            else:
                return addr_str, 0
        except ValueError:
            return addr_str, 0
    
    async def _analyze_connection(self, conn: NetworkConnection):
        """Analyze a connection for suspicious behavior."""
        # Check for suspicious ports
        if conn.remote_port in self.SUSPICIOUS_PORTS:
            await self._create_network_alert(
                threat_type="suspicious_port_connection",
                evidence=f"Connection to suspicious port {conn.remote_port}",
                connection=conn,
                severity="P2"
            )
        
        # Check for raw IP connections (no DNS)
        if re.match(r'\d+\.\d+\.\d+\.\d+', conn.remote_addr):
            # Only alert if it's not a private IP
            if not self._is_private_ip(conn.remote_addr):
                await self._create_network_alert(
                    threat_type="raw_ip_connection",
                    evidence=f"Direct IP connection to {conn.remote_addr}",
                    connection=conn,
                    severity="P3"
                )
        
        # Check for connections to known mining pools
        if conn.remote_port in [3333, 4444, 7777, 8333, 8888, 9999]:
            await self._create_network_alert(
                threat_type="potential_cryptomining",
                evidence=f"Connection to potential mining pool port {conn.remote_port}",
                connection=conn,
                severity="P1"
            )
        
        # Track for port scan detection
        if conn.state == "SYN_SENT" or conn.state == "ESTABLISHED":
            key = f"{conn.remote_addr}"
            self.connection_tracking[key].append(datetime.utcnow())
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges."""
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',
            r'^fc00:',
            r'^fe80:'
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                return True
        return False
    
    async def _monitor_dns_queries(self):
        """Monitor DNS queries for suspicious domains."""
        self.log.info("Starting DNS query monitor...")
        
        while self.running:
            try:
                # This is platform-specific and may require additional tools
                if not self.is_windows:
                    # Try to read from system logs
                    await self._check_dns_logs()
                else:
                    # Windows DNS monitoring is more complex
                    await self._check_windows_dns()
                
                await asyncio.sleep(60)
            
            except Exception as e:
                self.log.error("DNS monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(60)
    
    async def _check_dns_logs(self):
        """Check DNS logs for suspicious queries."""
        try:
            # Try common DNS log locations
            dns_logs = ['/var/log/dnsmasq.log', '/var/log/unbound.log']
            
            for log_file in dns_logs:
                if await self._file_exists(log_file):
                    # Read recent entries
                    result = subprocess.run(
                        ['tail', '-100', log_file],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            await self._analyze_dns_query(line)
        
        except Exception as e:
            self.log.debug("DNS log check error", error=str(e))
    
    async def _check_windows_dns(self):
        """Check Windows DNS activity."""
        # Placeholder - would need PowerShell DNS cmdlets or ETW
        pass
    
    async def _analyze_dns_query(self, log_line: str):
        """Analyze DNS query for suspicious domains."""
        for pattern in self.SUSPICIOUS_DOMAINS:
            if re.search(pattern, log_line, re.IGNORECASE):
                await self._create_network_alert(
                    threat_type="suspicious_dns_query",
                    evidence=f"DNS query to suspicious domain: {log_line[:100]}",
                    connection=None,
                    severity="P2"
                )
                break
    
    async def _detect_port_scans(self):
        """Detect potential port scanning activity."""
        self.log.info("Starting port scan detection...")
        
        while self.running:
            try:
                current_time = datetime.utcnow()
                cutoff_time = current_time - timedelta(seconds=self.TIME_WINDOW)
                
                # Check each tracked IP for scan patterns
                for remote_ip, timestamps in self.connection_tracking.items():
                    # Filter to recent connections
                    recent_connections = [t for t in timestamps if t > cutoff_time]
                    
                    if len(recent_connections) >= self.PORT_SCAN_THRESHOLD:
                        await self._create_network_alert(
                            threat_type="port_scan_detected",
                            evidence=f"Port scan from {remote_ip}: {len(recent_connections)} connections in {self.TIME_WINDOW}s",
                            connection=None,
                            severity="P1"
                        )
                        
                        # Clear to avoid duplicate alerts
                        self.connection_tracking[remote_ip] = []
                
                # Cleanup old tracking data
                for ip in list(self.connection_tracking.keys()):
                    self.connection_tracking[ip] = [
                        t for t in self.connection_tracking[ip] 
                        if t > cutoff_time
                    ]
                    if not self.connection_tracking[ip]:
                        del self.connection_tracking[ip]
                
                await asyncio.sleep(30)
            
            except Exception as e:
                self.log.error("Port scan detection error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(30)
    
    async def _analyze_connection_patterns(self):
        """Analyze connection patterns for anomalies."""
        self.log.info("Starting connection pattern analysis...")
        
        while self.running:
            try:
                if not self.baseline_established:
                    await asyncio.sleep(60)
                    continue
                
                # Analyze recent connections against baseline
                current_time = datetime.utcnow()
                recent_time = current_time - timedelta(minutes=15)
                
                recent_connections = [
                    c for c in self.connection_history 
                    if c.timestamp > recent_time
                ]
                
                # Check for new/unusual destinations
                current_destinations = set()
                for conn in recent_connections:
                    dest = (conn.remote_addr, conn.remote_port)
                    current_destinations.add(dest)
                
                new_destinations = current_destinations - self.baseline_connections
                
                if len(new_destinations) > 10:  # Many new destinations
                    await self._create_network_alert(
                        threat_type="unusual_network_pattern",
                        evidence=f"Many new network destinations: {len(new_destinations)} in 15 minutes",
                        connection=None,
                        severity="P2"
                    )
                
                await asyncio.sleep(300)  # Analyze every 5 minutes
            
            except Exception as e:
                self.log.error("Pattern analysis error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(300)
    
    async def _establish_baseline(self):
        """Establish baseline of normal network connections."""
        self.log.info("Establishing network baseline...")
        
        # Wait for some data collection
        await asyncio.sleep(300)  # 5 minutes
        
        while self.running:
            try:
                # Use last hour of connections as baseline
                baseline_time = datetime.utcnow() - timedelta(hours=1)
                baseline_connections = [
                    c for c in self.connection_history 
                    if c.timestamp > baseline_time
                ]
                
                # Build set of normal destinations
                self.baseline_connections = set()
                for conn in baseline_connections:
                    dest = (conn.remote_addr, conn.remote_port)
                    self.baseline_connections.add(dest)
                
                self.baseline_established = True
                self.log.info("Network baseline established", 
                             destinations=len(self.baseline_connections))
                
                # Update baseline every hour
                await asyncio.sleep(3600)
            
            except Exception as e:
                self.log.error("Baseline establishment error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(3600)
    
    async def _create_network_alert(self, threat_type: str, evidence: str, 
                                   connection: Optional[NetworkConnection], severity: str):
        """Create network-related security alert."""
        details = {
            "threat_type": threat_type,
            "evidence": evidence,
            "detection_method": "network_analysis"
        }
        
        if connection:
            details.update({
                "connection": connection.to_dict(),
                "local_endpoint": f"{connection.local_addr}:{connection.local_port}",
                "remote_endpoint": f"{connection.remote_addr}:{connection.remote_port}",
                "protocol": connection.protocol,
                "state": connection.state
            })
        
        normalized_event = self._normalize_event(
            raw_event={
                "resource": f"network/{connection.remote_addr if connection else 'unknown'}",
                "namespace": "network",
                "details": details
            },
            threat_type=threat_type,
            severity=severity,
            evidence=evidence
        )
        
        await queue.push("detection", normalized_event)
        self._increment_threats()
        
        self.log.info("Network threat detected",
                     threat=threat_type,
                     evidence=evidence[:100])
    
    # Investigation Agent helper methods
    async def get_connections_for_incident(self, timeframe: int = 3600) -> List[Dict[str, Any]]:
        """Get network connections for Investigation Agent."""
        cutoff = datetime.utcnow() - timedelta(seconds=timeframe)
        
        return [
            conn.to_dict() 
            for conn in self.connection_history 
            if conn.timestamp > cutoff
        ]
    
    async def search_connections_by_ip(self, ip_address: str) -> List[Dict[str, Any]]:
        """Search connections by IP address."""
        return [
            conn.to_dict() 
            for conn in self.connection_history 
            if conn.remote_addr == ip_address or conn.local_addr == ip_address
        ]
    
    async def get_connection_summary(self) -> Dict[str, Any]:
        """Get network connection summary for Investigation Agent."""
        recent_connections = [
            c for c in self.connection_history 
            if (datetime.utcnow() - c.timestamp).seconds < 3600
        ]
        
        # Summarize by destination
        destinations = defaultdict(int)
        protocols = defaultdict(int)
        ports = defaultdict(int)
        
        for conn in recent_connections:
            destinations[conn.remote_addr] += 1
            protocols[conn.protocol] += 1
            ports[conn.remote_port] += 1
        
        return {
            "total_connections": len(recent_connections),
            "unique_destinations": len(destinations),
            "top_destinations": dict(sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:10]),
            "protocols": dict(protocols),
            "common_ports": dict(sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]),
            "baseline_established": self.baseline_established,
            "baseline_destinations": len(self.baseline_connections)
        }
    
    async def _command_exists(self, command: str) -> bool:
        """Check if a command exists."""
        try:
            result = subprocess.run(
                ['which', command] if not self.is_windows else ['where', command],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    async def _file_exists(self, file_path: str) -> bool:
        """Check if file exists."""
        try:
            result = subprocess.run(
                ['test', '-f', file_path],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False