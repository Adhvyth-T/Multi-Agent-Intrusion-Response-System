# collectors/log_collector.py
"""
Log Collector - Aggregates logs from multiple sources for Investigation Agent.
Cross-platform log collection from containers, system logs, and applications.
"""

import asyncio
import subprocess
import json
import re
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
import platform

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


class LogCollector(BaseEventCollector):
    """
    Collect and analyze logs from multiple sources.
    
    Sources:
    - Docker container logs
    - System logs (journalctl/Windows Event Log)
    - Application logs (nginx, apache, etc.)
    - Security logs
    - Custom application logs
    
    Features:
    - Real-time log streaming
    - Historical log analysis
    - Suspicious pattern detection
    - Log correlation across sources
    """
    
    # Suspicious patterns in logs
    SUSPICIOUS_PATTERNS = {
        'web_attack': [
            r'union\s+select', r'<script.*>', r'\.\.\/\.\.\/', r'exec\(',
            r'system\(', r'cmd=', r'shell_exec', r'passthru\('
        ],
        'authentication_failure': [
            r'authentication\s+(failed|failure)', r'invalid\s+(user|login)',
            r'permission\s+denied', r'access\s+denied', r'unauthorized'
        ],
        'privilege_escalation': [
            r'sudo\s+.*', r'su\s+.*', r'privilege.*escalat', r'admin.*access'
        ],
        'data_exfiltration': [
            r'data\s+export', r'database\s+dump', r'sensitive.*access',
            r'download.*\d+\s+mb', r'large\s+file\s+transfer'
        ],
        'reconnaissance': [
            r'directory\s+listing', r'robots\.txt', r'\.well-known',
            r'scan.*attempt', r'enumerate', r'reconnaissance'
        ]
    }
    
    # Log severity mapping
    SEVERITY_MAP = {
        'CRITICAL': 'P1',
        'ERROR': 'P2',
        'WARNING': 'P3',
        'INFO': 'P4',
        'DEBUG': 'P4'
    }
    
    def __init__(self, log_paths: Optional[List[str]] = None):
        super().__init__(name="log_collector")
        self.log_paths = log_paths or []
        self.monitoring_tasks = []
        self.is_windows = platform.system() == "Windows"
        self.container_log_cache = {}
        
        # Default log paths by platform
        self._setup_default_paths()
    
    def _setup_default_paths(self):
        """Setup default log paths based on platform."""
        if self.is_windows:
            # Windows default log locations
            self.system_logs = ["System", "Security", "Application"]  # Event Log names
            self.default_log_paths = [
                "C:\\inetpub\\logs\\LogFiles\\W3SVC1\\*.log",  # IIS
                "C:\\ProgramData\\Docker\\containers\\*\\*-json.log",  # Docker on Windows
                "C:\\logs\\*.log"  # Generic application logs
            ]
        else:
            # Linux/WSL default log locations
            self.system_logs = ["/var/log/syslog", "/var/log/auth.log"]
            self.default_log_paths = [
                "/var/log/nginx/*.log",
                "/var/log/apache2/*.log",
                "/var/log/docker/*.log",
                "/var/log/containers/*/*.log",
                "/var/log/*.log"
            ]
        
        self.log_paths.extend(self.default_log_paths)
    
    async def start(self) -> None:
        """Start log collection."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        self.log.info("Log collector starting...", 
                     platform=platform.system(),
                     paths=len(self.log_paths))
        
        # Start all monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._monitor_container_logs()),
            asyncio.create_task(self._monitor_system_logs()),
            asyncio.create_task(self._monitor_application_logs()),
            asyncio.create_task(self._analyze_historical_logs()),
        ]
        
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def stop(self) -> None:
        """Stop log collection."""
        self.running = False
        
        # Cancel all tasks
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.log.info("Log collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Check if we can access logs
            accessible_sources = 0
            total_sources = len(self.log_paths) + len(self.system_logs)
            
            # Test Docker logs access
            try:
                result = subprocess.run(
                    ['docker', 'ps', '-q'],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    accessible_sources += 1
            except Exception:
                pass
            
            # Test system logs access
            if not self.is_windows:
                for log_file in self.system_logs:
                    if os.path.exists(log_file) and os.access(log_file, os.R_OK):
                        accessible_sources += 1
            else:
                accessible_sources += len(self.system_logs)  # Assume Event Log accessible
            
            if accessible_sources == 0:
                return CollectorHealth(
                    status="unhealthy",
                    message="No log sources accessible",
                    details={"total_sources": total_sources}
                )
            elif accessible_sources < total_sources * 0.5:
                return CollectorHealth(
                    status="degraded",
                    message="Limited log sources accessible",
                    details={
                        "accessible": accessible_sources,
                        "total": total_sources
                    }
                )
            else:
                return CollectorHealth(
                    status="healthy",
                    message="Log collector operating normally",
                    details={
                        "accessible_sources": accessible_sources,
                        "total_sources": total_sources,
                        "events_processed": self.metrics.events_processed
                    }
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
            "log_aggregation": True,
            "real_time_logs": True,
            "historical_analysis": True,
            "pattern_detection": True,
            "cross_correlation": True,
            "forensic_timeline": True
        }
    
    async def _monitor_container_logs(self):
        """Monitor Docker container logs in real-time."""
        self.log.info("Starting container logs monitor...")
        
        while self.running:
            try:
                # Get list of running containers
                result = subprocess.run(
                    ['docker', 'ps', '--format', '{{.Names}}'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                if result.returncode == 0:
                    containers = [c.strip() for c in result.stdout.split('\n') if c.strip()]
                    
                    # Monitor logs from each container
                    tasks = []
                    for container in containers:
                        if container not in self.container_log_cache:
                            tasks.append(self._tail_container_logs(container))
                    
                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                
                await asyncio.sleep(10)
            
            except Exception as e:
                self.log.error("Container logs monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(10)
    
    async def _tail_container_logs(self, container: str):
        """Tail logs from a specific container."""
        self.log.debug("Starting log tail", container=container)
        self.container_log_cache[container] = True
        
        try:
            # Start tailing logs
            process = await asyncio.create_subprocess_exec(
                'docker', 'logs', '-f', '--since', '5m', container,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read lines and analyze
            while self.running:
                line = await process.stdout.readline()
                if not line:
                    break
                
                log_line = line.decode().strip()
                if log_line:
                    self._increment_events()
                    await self._analyze_log_line(
                        source=f"container/{container}",
                        line=log_line,
                        timestamp=datetime.utcnow()
                    )
            
            process.kill()
            await process.wait()
        
        except Exception as e:
            self.log.error("Container log tail error", 
                          container=container, error=str(e))
            self._increment_errors()
        finally:
            self.container_log_cache.pop(container, None)
    
    async def _monitor_system_logs(self):
        """Monitor system logs."""
        self.log.info("Starting system logs monitor...")
        
        while self.running:
            try:
                if self.is_windows:
                    await self._monitor_windows_event_log()
                else:
                    await self._monitor_linux_system_logs()
                
                await asyncio.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                self.log.error("System logs monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(30)
    
    async def _monitor_windows_event_log(self):
        """Monitor Windows Event Log."""
        for log_name in self.system_logs:
            try:
                # Get recent events (last 5 minutes)
                cmd = [
                    'powershell', '-Command',
                    f"Get-WinEvent -LogName {log_name} -MaxEvents 100 | "
                    f"Where-Object {{$_.TimeCreated -gt (Get-Date).AddMinutes(-5)}} | "
                    f"ConvertTo-Json"
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    try:
                        events = json.loads(result.stdout)
                        if not isinstance(events, list):
                            events = [events]
                        
                        for event in events:
                            self._increment_events()
                            await self._analyze_windows_event(event)
                    
                    except json.JSONDecodeError:
                        pass
            
            except Exception as e:
                self.log.debug("Windows event log error", log=log_name, error=str(e))
    
    async def _monitor_linux_system_logs(self):
        """Monitor Linux system logs."""
        try:
            # Use journalctl for systemd systems
            cmd = ['journalctl', '-f', '--since', '5 minutes ago', '-o', 'json']
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Read for a short time then return
            try:
                for _ in range(100):  # Limit to avoid blocking
                    line = await asyncio.wait_for(process.stdout.readline(), timeout=1.0)
                    if not line:
                        break
                    
                    try:
                        event = json.loads(line.decode())
                        self._increment_events()
                        await self._analyze_systemd_event(event)
                    except json.JSONDecodeError:
                        continue
            
            except asyncio.TimeoutError:
                pass
            
            process.kill()
            await process.wait()
        
        except Exception as e:
            self.log.debug("Linux system logs error", error=str(e))
    
    async def _monitor_application_logs(self):
        """Monitor application log files."""
        self.log.info("Starting application logs monitor...")
        
        # For now, just check if files exist and are growing
        # Full implementation would use file watching
        while self.running:
            try:
                for log_path in self.log_paths:
                    if '*' not in log_path and os.path.exists(log_path):
                        await self._check_log_file_growth(log_path)
                
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                self.log.error("Application logs monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(60)
    
    async def _check_log_file_growth(self, file_path: str):
        """Check if log file has new content."""
        try:
            stat = os.stat(file_path)
            current_size = stat.st_size
            current_mtime = stat.st_mtime
            
            # Simple tracking of file changes
            cache_key = f"file_{file_path}"
            last_size = getattr(self, cache_key, 0)
            
            if current_size > last_size:
                # File has grown, read new content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    new_lines = f.readlines()
                    
                    for line in new_lines[-50:]:  # Analyze last 50 lines
                        self._increment_events()
                        await self._analyze_log_line(
                            source=f"file/{Path(file_path).name}",
                            line=line.strip(),
                            timestamp=datetime.fromtimestamp(current_mtime)
                        )
                
                setattr(self, cache_key, current_size)
        
        except Exception as e:
            self.log.debug("Log file check error", file=file_path, error=str(e))
    
    async def _analyze_historical_logs(self):
        """Periodic analysis of historical logs for Investigation Agent."""
        self.log.info("Starting historical log analysis...")
        
        while self.running:
            try:
                # Run every 5 minutes
                await asyncio.sleep(300)
                
                # Analyze last hour of logs for patterns
                end_time = datetime.utcnow()
                start_time = end_time - timedelta(hours=1)
                
                historical_events = await self._collect_historical_logs(start_time, end_time)
                
                if historical_events:
                    analysis = await self._analyze_log_patterns(historical_events)
                    
                    if analysis.get('suspicious_activity'):
                        await self._create_investigation_alert(analysis)
            
            except Exception as e:
                self.log.error("Historical analysis error", error=str(e))
                self._increment_errors()
    
    async def _collect_historical_logs(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Collect logs from specified time period."""
        events = []
        
        try:
            # Collect Docker logs for time period
            for container in list(self.container_log_cache.keys()):
                try:
                    since = start_time.strftime('%Y-%m-%dT%H:%M:%S')
                    until = end_time.strftime('%Y-%m-%dT%H:%M:%S')
                    
                    result = subprocess.run([
                        'docker', 'logs', 
                        '--since', since,
                        '--until', until,
                        container
                    ], capture_output=True, text=True, timeout=10)
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if line.strip():
                                events.append({
                                    'source': f'container/{container}',
                                    'message': line.strip(),
                                    'timestamp': datetime.utcnow()  # Approximate
                                })
                
                except Exception:
                    continue
        
        except Exception as e:
            self.log.error("Historical collection error", error=str(e))
        
        return events
    
    async def _analyze_log_line(self, source: str, line: str, timestamp: datetime):
        """Analyze a single log line for threats."""
        line_lower = line.lower()
        
        # Check for suspicious patterns
        for threat_type, patterns in self.SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line_lower, re.IGNORECASE):
                    severity = self._determine_severity(line, threat_type)
                    
                    await self._create_log_alert(
                        source=source,
                        threat_type=threat_type,
                        evidence=line[:200],  # First 200 chars
                        severity=severity,
                        timestamp=timestamp
                    )
                    return
    
    async def _analyze_windows_event(self, event: Dict[str, Any]):
        """Analyze Windows Event Log entry."""
        event_id = event.get('Id', 0)
        level = event.get('LevelDisplayName', 'Information')
        message = event.get('Message', '')
        
        # Check for security-relevant events
        if event_id in [4625, 4648, 4771]:  # Failed logon attempts
            await self._create_log_alert(
                source="windows_event_log",
                threat_type="authentication_failure",
                evidence=f"Event {event_id}: {message[:200]}",
                severity='P2',
                timestamp=datetime.utcnow()
            )
    
    async def _analyze_systemd_event(self, event: Dict[str, Any]):
        """Analyze systemd journal event."""
        message = event.get('MESSAGE', '')
        priority = event.get('PRIORITY', '6')
        
        # Convert priority to severity
        priority_map = {'0': 'P1', '1': 'P1', '2': 'P1', '3': 'P2', '4': 'P3'}
        severity = priority_map.get(priority, 'P4')
        
        if int(priority) <= 3:  # Error level or higher
            await self._analyze_log_line(
                source="systemd",
                line=message,
                timestamp=datetime.utcnow()
            )
    
    async def _analyze_log_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns across multiple log events."""
        analysis = {
            'total_events': len(events),
            'suspicious_activity': False,
            'patterns': {}
        }
        
        # Simple pattern analysis
        source_counts = {}
        threat_indicators = 0
        
        for event in events:
            source = event['source']
            source_counts[source] = source_counts.get(source, 0) + 1
            
            # Check for threat indicators
            message = event['message'].lower()
            for threat_type, patterns in self.SUSPICIOUS_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, message, re.IGNORECASE):
                        threat_indicators += 1
                        analysis['patterns'][threat_type] = analysis['patterns'].get(threat_type, 0) + 1
        
        # Determine if activity is suspicious
        if threat_indicators > 5 or len(analysis['patterns']) > 2:
            analysis['suspicious_activity'] = True
            analysis['threat_indicators'] = threat_indicators
        
        return analysis
    
    def _determine_severity(self, log_line: str, threat_type: str) -> str:
        """Determine severity based on log content and threat type."""
        high_severity_threats = ['web_attack', 'privilege_escalation', 'data_exfiltration']
        
        if threat_type in high_severity_threats:
            return 'P1'
        elif 'error' in log_line.lower() or 'critical' in log_line.lower():
            return 'P2'
        else:
            return 'P3'
    
    async def _create_log_alert(self, source: str, threat_type: str, 
                               evidence: str, severity: str, timestamp: datetime):
        """Create alert from log analysis."""
        normalized_event = self._normalize_event(
            raw_event={
                "resource": source,
                "namespace": "logs",
                "timestamp": timestamp.isoformat(),
                "details": {
                    "log_source": source,
                    "threat_type": threat_type,
                    "evidence": evidence,
                    "original_message": evidence
                }
            },
            threat_type=f"suspicious_log_{threat_type}",
            severity=severity,
            evidence=f"Suspicious pattern in logs: {evidence[:100]}"
        )
        
        await queue.push("detection", normalized_event)
        self._increment_threats()
        
        self.log.info("Suspicious log pattern detected",
                     source=source,
                     threat=threat_type,
                     evidence=evidence[:50])
    
    async def _create_investigation_alert(self, analysis: Dict[str, Any]):
        """Create alert from historical pattern analysis."""
        evidence = f"Pattern analysis: {analysis.get('threat_indicators', 0)} indicators across {analysis.get('total_events', 0)} events"
        
        normalized_event = self._normalize_event(
            raw_event={
                "resource": "log_analysis",
                "namespace": "investigation",
                "details": {
                    "analysis_type": "historical_pattern",
                    "total_events": analysis.get('total_events', 0),
                    "threat_indicators": analysis.get('threat_indicators', 0),
                    "patterns_detected": list(analysis.get('patterns', {}).keys())
                }
            },
            threat_type="suspicious_log_patterns",
            severity='P2',
            evidence=evidence
        )
        
        await queue.push("detection", normalized_event)
        self._increment_threats()
        
        self.log.info("Suspicious log patterns detected in historical analysis",
                     patterns=list(analysis.get('patterns', {}).keys()),
                     indicators=analysis.get('threat_indicators', 0))
    
    # Investigation Agent helper methods
    async def get_logs_for_incident(self, resource: str, time_range: int = 3600) -> List[Dict[str, Any]]:
        """Get logs related to an incident for Investigation Agent."""
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(seconds=time_range)
        
        return await self._collect_historical_logs(start_time, end_time)
    
    async def search_logs_by_pattern(self, pattern: str, time_range: int = 3600) -> List[Dict[str, Any]]:
        """Search logs by regex pattern for Investigation Agent."""
        logs = await self.get_logs_for_incident("*", time_range)
        
        matches = []
        for log_entry in logs:
            if re.search(pattern, log_entry.get('message', ''), re.IGNORECASE):
                matches.append(log_entry)
        
        return matches