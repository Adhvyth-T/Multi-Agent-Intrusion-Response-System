# collectors/host_collector.py
"""
Host Collector - Traditional host-level monitoring for processes, files, services.
Cross-platform host monitoring for Investigation Agent and threat detection.
"""

import asyncio
import subprocess
import json
import re
import os
import psutil
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from collections import defaultdict
import platform
import hashlib

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


@dataclass
class ProcessInfo:
    """Represents a process."""
    pid: int
    name: str
    cmdline: str
    cpu_percent: float
    memory_mb: float
    user: str
    status: str
    create_time: datetime
    parent_pid: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'pid': self.pid,
            'name': self.name,
            'cmdline': self.cmdline,
            'cpu_percent': self.cpu_percent,
            'memory_mb': self.memory_mb,
            'user': self.user,
            'status': self.status,
            'create_time': self.create_time.isoformat(),
            'parent_pid': self.parent_pid
        }


class HostCollector(BaseEventCollector):
    """
    Monitor host-level activities for suspicious behavior.
    
    Capabilities:
    - Process monitoring and analysis
    - File system monitoring (basic)
    - Service monitoring
    - User activity tracking
    - Registry monitoring (Windows)
    - Resource usage anomalies
    - Persistence mechanism detection
    """
    
    # Suspicious process patterns
    SUSPICIOUS_PROCESSES = {
        'cryptominer': [
            r'xmrig', r'minerd', r'cpuminer', r'ethminer', r'ccminer',
            r'cgminer', r'bfgminer', r'cryptonight', r'monero'
        ],
        'backdoor': [
            r'nc\.exe', r'netcat', r'powershell.*-enc', r'cmd\.exe.*>&',
            r'bash.*-i', r'sh.*-i', r'socat', r'/dev/tcp/'
        ],
        'persistence': [
            r'schtasks', r'crontab', r'at\.exe', r'reg\.exe.*run',
            r'startup', r'autorun', r'service.*install'
        ],
        'recon': [
            r'whoami', r'ipconfig', r'ifconfig', r'netstat', r'ps.*aux',
            r'tasklist', r'systeminfo', r'uname.*-a'
        ],
        'privilege_escalation': [
            r'sudo', r'su\s+', r'runas', r'psexec', r'wmic.*process'
        ]
    }
    
    # Suspicious file paths
    SUSPICIOUS_PATHS = {
        'windows': [
            r'C:\\Windows\\Temp\\.*\.exe',
            r'C:\\Users\\.*\\AppData\\Local\\Temp\\.*\.exe',
            r'C:\\ProgramData\\.*\.exe',
            r'%TEMP%\\.*\.exe',
            r'%APPDATA%\\.*\.exe'
        ],
        'linux': [
            r'/tmp/.*',
            r'/var/tmp/.*',
            r'/dev/shm/.*',
            r'/home/.*\.hidden/',
            r'.*\.sh$'
        ]
    }
    
    # High resource usage thresholds
    CPU_THRESHOLD = 80.0  # %
    MEMORY_THRESHOLD = 80.0  # %
    
    def __init__(self):
        super().__init__(name="host_collector")
        self.is_windows = platform.system() == "Windows"
        self.monitoring_tasks = []
        self.process_history: List[ProcessInfo] = []
        self.baseline_processes: Set[str] = set()
        self.file_hashes: Dict[str, str] = {}
        self.service_states: Dict[str, str] = {}
        
    async def start(self) -> None:
        """Start host monitoring."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        self.log.info("Host collector starting...", 
                     platform=platform.system())
        
        # Start monitoring tasks
        self.monitoring_tasks = [
            asyncio.create_task(self._monitor_processes()),
            asyncio.create_task(self._monitor_services()),
            asyncio.create_task(self._monitor_file_changes()),
            asyncio.create_task(self._monitor_user_activity()),
            asyncio.create_task(self._monitor_system_resources()),
        ]
        
        # Add Windows-specific monitoring
        if self.is_windows:
            self.monitoring_tasks.append(
                asyncio.create_task(self._monitor_registry())
            )
        
        await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
    
    async def stop(self) -> None:
        """Stop host monitoring."""
        self.running = False
        
        # Cancel all tasks
        for task in self.monitoring_tasks:
            if not task.done():
                task.cancel()
        
        if self.monitoring_tasks:
            await asyncio.gather(*self.monitoring_tasks, return_exceptions=True)
        
        self.log.info("Host collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Check if we can get system information
            cpu_count = psutil.cpu_count()
            memory = psutil.virtual_memory()
            
            if cpu_count and memory:
                # Check if we're collecting process data
                recent_processes = len([
                    p for p in self.process_history 
                    if (datetime.utcnow() - p.create_time).seconds < 300
                ])
                
                return CollectorHealth(
                    status="healthy",
                    message="Host collector operating normally",
                    details={
                        "cpu_cores": cpu_count,
                        "memory_gb": round(memory.total / (1024**3), 1),
                        "memory_available": round(memory.available / (1024**3), 1),
                        "recent_processes": recent_processes,
                        "total_processes_tracked": len(self.process_history)
                    }
                )
            else:
                return CollectorHealth(
                    status="degraded",
                    message="Limited system information available",
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
            "network_monitoring": False,
            "file_monitoring": True,
            "syscall_monitoring": False,
            "service_monitoring": True,
            "user_activity": True,
            "resource_monitoring": True,
            "registry_monitoring": self.is_windows,
            "persistence_detection": True,
            "anomaly_detection": True
        }
    
    async def _monitor_processes(self):
        """Monitor running processes for suspicious activity."""
        self.log.info("Starting process monitor...")
        
        while self.running:
            try:
                current_processes = []
                
                # Get all processes
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 
                                                'memory_info', 'username', 'status', 'create_time', 'ppid']):
                    try:
                        pinfo = proc.info
                        if pinfo['pid'] == 0:  # Skip system idle process
                            continue
                        
                        cmdline = ' '.join(pinfo['cmdline']) if pinfo['cmdline'] else pinfo['name']
                        memory_mb = pinfo['memory_info'].rss / (1024 * 1024) if pinfo['memory_info'] else 0
                        
                        process_info = ProcessInfo(
                            pid=pinfo['pid'],
                            name=pinfo['name'] or 'unknown',
                            cmdline=cmdline[:200],  # Truncate long command lines
                            cpu_percent=pinfo['cpu_percent'] or 0.0,
                            memory_mb=memory_mb,
                            user=pinfo['username'] or 'unknown',
                            status=pinfo['status'] or 'unknown',
                            create_time=datetime.fromtimestamp(pinfo['create_time']) if pinfo['create_time'] else datetime.utcnow(),
                            parent_pid=pinfo['ppid'] or 0
                        )
                        
                        current_processes.append(process_info)
                        self._increment_events()
                        
                        # Analyze process for threats
                        await self._analyze_process(process_info)
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        self.log.debug("Process info error", error=str(e))
                        continue
                
                # Update process history
                self.process_history = current_processes
                
                # Establish baseline if not done
                if not self.baseline_processes:
                    self.baseline_processes = {p.name for p in current_processes}
                    self.log.info("Process baseline established", 
                                 count=len(self.baseline_processes))
                
                await asyncio.sleep(30)  # Check every 30 seconds
            
            except Exception as e:
                self.log.error("Process monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(30)
    
    async def _analyze_process(self, process: ProcessInfo):
        """Analyze a process for suspicious behavior."""
        # Check command line for suspicious patterns
        cmdline_lower = process.cmdline.lower()
        
        for threat_type, patterns in self.SUSPICIOUS_PROCESSES.items():
            for pattern in patterns:
                if re.search(pattern, cmdline_lower, re.IGNORECASE):
                    severity = 'P1' if threat_type in ['cryptominer', 'backdoor'] else 'P2'
                    
                    await self._create_host_alert(
                        threat_type=f"suspicious_process_{threat_type}",
                        evidence=f"Suspicious process: {process.cmdline[:100]}",
                        details={
                            "process": process.to_dict(),
                            "pattern_matched": pattern
                        },
                        severity=severity
                    )
                    return
        
        # Check for high resource usage
        if process.cpu_percent > self.CPU_THRESHOLD:
            await self._create_host_alert(
                threat_type="high_cpu_usage",
                evidence=f"High CPU usage: {process.name} using {process.cpu_percent:.1f}%",
                details={"process": process.to_dict()},
                severity='P3'
            )
        
        if process.memory_mb > 1024:  # > 1GB memory usage
            await self._create_host_alert(
                threat_type="high_memory_usage",
                evidence=f"High memory usage: {process.name} using {process.memory_mb:.0f} MB",
                details={"process": process.to_dict()},
                severity='P3'
            )
        
        # Check for new processes not in baseline
        if process.name not in self.baseline_processes:
            await self._create_host_alert(
                threat_type="new_process_detected",
                evidence=f"New process: {process.name}",
                details={"process": process.to_dict()},
                severity='P4'
            )
    
    async def _monitor_services(self):
        """Monitor system services for changes."""
        self.log.info("Starting service monitor...")
        
        while self.running:
            try:
                current_services = {}
                
                if self.is_windows:
                    # Windows services
                    result = subprocess.run(
                        ['sc', 'query', 'state=', 'all'],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        current_services = self._parse_windows_services(result.stdout)
                else:
                    # Linux systemd services
                    try:
                        result = subprocess.run(
                            ['systemctl', 'list-units', '--type=service', '--no-pager'],
                            capture_output=True,
                            text=True,
                            timeout=30
                        )
                        
                        if result.returncode == 0:
                            current_services = self._parse_systemd_services(result.stdout)
                    except FileNotFoundError:
                        # systemctl not available, try service command
                        pass
                
                # Check for service changes
                for service_name, state in current_services.items():
                    if service_name in self.service_states:
                        if self.service_states[service_name] != state:
                            await self._create_host_alert(
                                threat_type="service_state_change",
                                evidence=f"Service {service_name} changed from {self.service_states[service_name]} to {state}",
                                details={
                                    "service": service_name,
                                    "old_state": self.service_states[service_name],
                                    "new_state": state
                                },
                                severity='P3'
                            )
                
                self.service_states = current_services
                await asyncio.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                self.log.error("Service monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(300)
    
    def _parse_windows_services(self, output: str) -> Dict[str, str]:
        """Parse Windows sc query output."""
        services = {}
        current_service = None
        
        for line in output.split('\n'):
            line = line.strip()
            if line.startswith('SERVICE_NAME:'):
                current_service = line.split(':', 1)[1].strip()
            elif line.startswith('STATE') and current_service:
                state_info = line.split(':', 1)[1].strip()
                state = state_info.split()[1] if len(state_info.split()) > 1 else 'UNKNOWN'
                services[current_service] = state
                current_service = None
        
        return services
    
    def _parse_systemd_services(self, output: str) -> Dict[str, str]:
        """Parse systemctl list-units output."""
        services = {}
        
        for line in output.split('\n')[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 4 and parts[0].endswith('.service'):
                service_name = parts[0]
                state = parts[2]  # SUB state
                services[service_name] = state
        
        return services
    
    async def _monitor_file_changes(self):
        """Monitor critical files for changes."""
        self.log.info("Starting file monitor...")
        
        # Critical files to monitor
        if self.is_windows:
            critical_files = [
                r'C:\Windows\System32\drivers\etc\hosts',
                r'C:\Windows\win.ini',
                r'C:\Windows\system.ini'
            ]
        else:
            critical_files = [
                '/etc/passwd',
                '/etc/shadow',
                '/etc/sudoers',
                '/etc/hosts',
                '/etc/crontab',
                '/root/.ssh/authorized_keys',
                '/home/*/.ssh/authorized_keys'
            ]
        
        while self.running:
            try:
                for file_path in critical_files:
                    if '*' in file_path:
                        # Handle wildcards (basic implementation)
                        continue
                    
                    if os.path.exists(file_path):
                        current_hash = await self._get_file_hash(file_path)
                        
                        if file_path in self.file_hashes:
                            if self.file_hashes[file_path] != current_hash:
                                await self._create_host_alert(
                                    threat_type="critical_file_modified",
                                    evidence=f"Critical file modified: {file_path}",
                                    details={
                                        "file_path": file_path,
                                        "old_hash": self.file_hashes[file_path],
                                        "new_hash": current_hash
                                    },
                                    severity='P1'
                                )
                        
                        self.file_hashes[file_path] = current_hash
                
                await asyncio.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                self.log.error("File monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(300)
    
    async def _get_file_hash(self, file_path: str) -> str:
        """Get SHA256 hash of file."""
        try:
            hasher = hashlib.sha256()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return ""
    
    async def _monitor_user_activity(self):
        """Monitor user activity and authentication events."""
        self.log.info("Starting user activity monitor...")
        
        while self.running:
            try:
                if self.is_windows:
                    await self._monitor_windows_logons()
                else:
                    await self._monitor_linux_auth()
                
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                self.log.error("User activity monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(60)
    
    async def _monitor_windows_logons(self):
        """Monitor Windows logon events."""
        try:
            cmd = [
                'powershell', '-Command',
                'Get-WinEvent -FilterHashtable @{LogName="Security"; ID=4624,4625} -MaxEvents 10 | ConvertTo-Json'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and result.stdout.strip():
                try:
                    events = json.loads(result.stdout)
                    if not isinstance(events, list):
                        events = [events]
                    
                    for event in events:
                        if event.get('Id') == 4625:  # Failed logon
                            await self._create_host_alert(
                                threat_type="authentication_failure",
                                evidence=f"Failed logon attempt: {event.get('Message', '')[:200]}",
                                details={"event": event},
                                severity='P2'
                            )
                
                except json.JSONDecodeError:
                    pass
        
        except Exception as e:
            self.log.debug("Windows logon monitor error", error=str(e))
    
    async def _monitor_linux_auth(self):
        """Monitor Linux authentication logs."""
        try:
            auth_files = ['/var/log/auth.log', '/var/log/secure']
            
            for auth_file in auth_files:
                if os.path.exists(auth_file):
                    # Read last 50 lines
                    result = subprocess.run(
                        ['tail', '-50', auth_file],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if result.returncode == 0:
                        for line in result.stdout.split('\n'):
                            if 'authentication failure' in line.lower() or 'failed password' in line.lower():
                                await self._create_host_alert(
                                    threat_type="authentication_failure",
                                    evidence=f"Auth failure: {line[:200]}",
                                    details={"log_line": line},
                                    severity='P2'
                                )
                    break  # Only check first available file
        
        except Exception as e:
            self.log.debug("Linux auth monitor error", error=str(e))
    
    async def _monitor_system_resources(self):
        """Monitor system resource usage."""
        self.log.info("Starting system resource monitor...")
        
        while self.running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > 90:
                    await self._create_host_alert(
                        threat_type="high_system_cpu",
                        evidence=f"High system CPU usage: {cpu_percent:.1f}%",
                        details={"cpu_percent": cpu_percent},
                        severity='P3'
                    )
                
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > 90:
                    await self._create_host_alert(
                        threat_type="high_system_memory",
                        evidence=f"High system memory usage: {memory.percent:.1f}%",
                        details={"memory_percent": memory.percent},
                        severity='P3'
                    )
                
                # Disk usage
                disk = psutil.disk_usage('/')
                if disk.percent > 90:
                    await self._create_host_alert(
                        threat_type="high_disk_usage",
                        evidence=f"High disk usage: {disk.percent:.1f}%",
                        details={"disk_percent": disk.percent},
                        severity='P3'
                    )
                
                await asyncio.sleep(60)  # Check every minute
            
            except Exception as e:
                self.log.error("Resource monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(60)
    
    async def _monitor_registry(self):
        """Monitor Windows registry for changes."""
        if not self.is_windows:
            return
        
        self.log.info("Starting Windows registry monitor...")
        
        # Key registry locations to monitor
        registry_keys = [
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            r'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
            r'HKLM\SYSTEM\CurrentControlSet\Services'
        ]
        
        while self.running:
            try:
                for key_path in registry_keys:
                    try:
                        # Query registry key
                        result = subprocess.run(
                            ['reg', 'query', key_path],
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        
                        if result.returncode == 0:
                            # Simple check for new entries
                            # (Full implementation would track changes)
                            lines = result.stdout.split('\n')
                            if len(lines) > 10:  # Many entries might be suspicious
                                await self._create_host_alert(
                                    threat_type="registry_activity",
                                    evidence=f"Many registry entries in {key_path}: {len(lines)}",
                                    details={"registry_key": key_path, "entry_count": len(lines)},
                                    severity='P4'
                                )
                    
                    except Exception as e:
                        self.log.debug("Registry query error", key=key_path, error=str(e))
                
                await asyncio.sleep(300)  # Check every 5 minutes
            
            except Exception as e:
                self.log.error("Registry monitor error", error=str(e))
                self._increment_errors()
                await asyncio.sleep(300)
    
    async def _create_host_alert(self, threat_type: str, evidence: str, 
                                details: Dict[str, Any], severity: str):
        """Create host-related security alert."""
        normalized_event = self._normalize_event(
            raw_event={
                "resource": f"host/{platform.node()}",
                "namespace": "host",
                "details": {
                    "threat_type": threat_type,
                    "evidence": evidence,
                    "detection_method": "host_analysis",
                    "hostname": platform.node(),
                    "platform": platform.system(),
                    **details
                }
            },
            threat_type=threat_type,
            severity=severity,
            evidence=evidence
        )
        
        await queue.push("detection", normalized_event)
        self._increment_threats()
        
        self.log.info("Host threat detected",
                     threat=threat_type,
                     evidence=evidence[:100])
    
    # Investigation Agent helper methods
    async def get_process_snapshot(self) -> Dict[str, Any]:
        """Get current process snapshot for Investigation Agent."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_processes": len(self.process_history),
            "processes": [p.to_dict() for p in self.process_history],
            "high_cpu_processes": [
                p.to_dict() for p in self.process_history 
                if p.cpu_percent > 50.0
            ],
            "high_memory_processes": [
                p.to_dict() for p in self.process_history 
                if p.memory_mb > 500.0
            ]
        }
    
    async def get_system_info(self) -> Dict[str, Any]:
        """Get system information for Investigation Agent."""
        cpu_times = psutil.cpu_times()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot_time = datetime.fromtimestamp(psutil.boot_time())
        
        return {
            "hostname": platform.node(),
            "platform": platform.system(),
            "platform_version": platform.version(),
            "architecture": platform.machine(),
            "cpu_count": psutil.cpu_count(),
            "cpu_times": cpu_times._asdict(),
            "memory": {
                "total_gb": round(memory.total / (1024**3), 2),
                "available_gb": round(memory.available / (1024**3), 2),
                "percent_used": memory.percent
            },
            "disk": {
                "total_gb": round(disk.total / (1024**3), 2),
                "free_gb": round(disk.free / (1024**3), 2),
                "percent_used": disk.percent
            },
            "boot_time": boot_time.isoformat(),
            "uptime_hours": round((datetime.utcnow() - boot_time).total_seconds() / 3600, 1)
        }
    
    async def search_processes_by_name(self, process_name: str) -> List[Dict[str, Any]]:
        """Search processes by name pattern."""
        matches = []
        for process in self.process_history:
            if re.search(process_name, process.name, re.IGNORECASE) or \
               re.search(process_name, process.cmdline, re.IGNORECASE):
                matches.append(process.to_dict())
        return matches
    
    async def get_service_changes(self, timeframe: int = 3600) -> List[Dict[str, Any]]:
        """Get service state changes for Investigation Agent."""
        # This would require historical tracking
        # For now, return current service states
        return [
            {"service": name, "state": state} 
            for name, state in self.service_states.items()
        ]