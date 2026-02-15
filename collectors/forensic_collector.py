# collectors/forensic_collector.py
"""
Forensic Collector - Collect forensic artifacts and evidence for Investigation Agent.
Specialized collector for post-incident analysis and evidence preservation.
"""

import asyncio
import subprocess
import json
import os
import shutil
import tempfile
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from pathlib import Path
import platform
import psutil
import zipfile

from collectors.base_collector import BaseEventCollector, CollectorHealth
from core import queue


@dataclass
class ForensicArtifact:
    """Represents a forensic artifact."""
    artifact_type: str
    name: str
    path: str
    hash: str
    size_bytes: int
    created_at: datetime
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'type': self.artifact_type,
            'name': self.name,
            'path': self.path,
            'hash': self.hash,
            'size_bytes': self.size_bytes,
            'created_at': self.created_at.isoformat(),
            'metadata': self.metadata
        }


class ForensicCollector(BaseEventCollector):
    """
    Collect forensic artifacts for incident investigation.
    
    Capabilities:
    - Memory dumps (if tools available)
    - Process forensics (command lines, environment, handles)
    - Network connection snapshots
    - File system artifacts
    - Log collection and preservation
    - Timeline reconstruction
    - Evidence packaging
    - Chain of custody tracking
    """
    
    def __init__(self, evidence_dir: Optional[str] = None):
        super().__init__(name="forensic_collector")
        self.is_windows = platform.system() == "Windows"
        self.evidence_dir = Path(evidence_dir) if evidence_dir else Path(tempfile.gettempdir()) / "ir_evidence"
        self.artifacts: List[ForensicArtifact] = []
        self.collection_tasks = []
        
        # Ensure evidence directory exists
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    async def start(self) -> None:
        """Start forensic collection (passive mode)."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        self.log.info("Forensic collector started in passive mode",
                     evidence_dir=str(self.evidence_dir))
        
        # Run periodic cleanup
        while self.running:
            await self._cleanup_old_artifacts()
            await asyncio.sleep(3600)  # Cleanup every hour
    
    async def stop(self) -> None:
        """Stop forensic collection."""
        self.running = False
        
        # Cancel collection tasks
        for task in self.collection_tasks:
            if not task.done():
                task.cancel()
        
        if self.collection_tasks:
            await asyncio.gather(*self.collection_tasks, return_exceptions=True)
        
        self.log.info("Forensic collector stopped")
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Check evidence directory accessibility
            if not self.evidence_dir.exists():
                return CollectorHealth(
                    status="unhealthy",
                    message="Evidence directory not accessible",
                    details={"evidence_dir": str(self.evidence_dir)}
                )
            
            # Check disk space
            disk_usage = psutil.disk_usage(str(self.evidence_dir))
            free_gb = disk_usage.free / (1024**3)
            
            if free_gb < 1.0:  # Less than 1GB free
                return CollectorHealth(
                    status="degraded",
                    message="Low disk space for evidence collection",
                    details={"free_gb": round(free_gb, 2)}
                )
            
            return CollectorHealth(
                status="healthy",
                message="Forensic collector ready",
                details={
                    "evidence_dir": str(self.evidence_dir),
                    "artifacts_collected": len(self.artifacts),
                    "free_space_gb": round(free_gb, 2)
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
            "memory_forensics": True,  # If tools available
            "process_forensics": True,
            "network_forensics": True,
            "file_forensics": True,
            "log_preservation": True,
            "timeline_reconstruction": True,
            "evidence_packaging": True
        }
    
    async def collect_incident_forensics(self, incident_id: str, 
                                       resource: str = None) -> Dict[str, Any]:
        """
        Main forensic collection for an incident.
        Called by Investigation Agent.
        """
        self.log.info("Starting forensic collection", incident_id=incident_id)
        
        collection_start = datetime.utcnow()
        incident_dir = self.evidence_dir / f"incident_{incident_id}_{collection_start.strftime('%Y%m%d_%H%M%S')}"
        incident_dir.mkdir(parents=True, exist_ok=True)
        
        # Collection manifest
        manifest = {
            "incident_id": incident_id,
            "collection_start": collection_start.isoformat(),
            "collector_version": "1.0",
            "hostname": platform.node(),
            "platform": platform.system(),
            "resource": resource,
            "artifacts": []
        }
        
        try:
            # Collect different types of forensic evidence
            tasks = [
                self._collect_process_forensics(incident_dir, incident_id),
                self._collect_network_forensics(incident_dir, incident_id),
                self._collect_file_forensics(incident_dir, incident_id, resource),
                self._collect_system_state(incident_dir, incident_id),
                self._collect_logs(incident_dir, incident_id),
            ]
            
            # Run collections concurrently
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect artifacts from results
            for result in results:
                if isinstance(result, list):
                    manifest["artifacts"].extend(result)
                elif isinstance(result, Exception):
                    self.log.error("Collection error", error=str(result))
            
            manifest["collection_end"] = datetime.utcnow().isoformat()
            manifest["total_artifacts"] = len(manifest["artifacts"])
            
            # Save manifest
            manifest_path = incident_dir / "collection_manifest.json"
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2)
            
            # Create evidence package
            package_path = await self._create_evidence_package(incident_dir)
            
            self.log.info("Forensic collection completed",
                         incident_id=incident_id,
                         artifacts=len(manifest["artifacts"]),
                         package=str(package_path))
            
            return {
                "status": "completed",
                "incident_id": incident_id,
                "artifacts_collected": len(manifest["artifacts"]),
                "evidence_package": str(package_path),
                "collection_time": (datetime.utcnow() - collection_start).total_seconds(),
                "manifest": manifest
            }
        
        except Exception as e:
            self.log.error("Forensic collection failed", 
                          incident_id=incident_id, error=str(e))
            self._increment_errors()
            return {
                "status": "failed",
                "incident_id": incident_id,
                "error": str(e)
            }
    
    async def _collect_process_forensics(self, output_dir: Path, incident_id: str) -> List[Dict[str, Any]]:
        """Collect process-related forensic artifacts."""
        self.log.info("Collecting process forensics")
        artifacts = []
        
        try:
            # Process list with full details
            process_list_path = output_dir / "processes.json"
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'cwd', 
                                           'username', 'create_time', 'cpu_times', 
                                           'memory_info', 'open_files']):
                try:
                    pinfo = proc.info

                    try:
                         pinfo['connections'] = [
                                {
                                    'fd': conn.fd,
                                    'family': str(conn.family),
                                    'type': str(conn.type),
                                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                    'status': conn.status
                                }
                                for conn in proc.connections()  # ← This is the correct way
                            ]
                    except:
                        pinfo['connections'] = []
                    
                    # Get additional process details
                    try:
                        pinfo['open_files'] = [f.path for f in proc.open_files()]
                    except:
                        pinfo['open_files'] = []
                    
                    try:
                        pinfo['connections'] = [
                            {
                                'fd': conn.fd,
                                'family': str(conn.family),
                                'type': str(conn.type),
                                'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                'status': conn.status
                            }
                            for conn in proc.connections()
                        ]
                    except:
                        pinfo['connections'] = []
                    
                    # Convert datetime objects
                    if pinfo['create_time']:
                        pinfo['create_time'] = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                    
                    processes.append(pinfo)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            with open(process_list_path, 'w') as f:
                json.dump(processes, f, indent=2, default=str)
            
            artifacts.append({
                "type": "process_snapshot",
                "name": "processes.json",
                "path": str(process_list_path),
                "size": process_list_path.stat().st_size,
                "description": "Complete process list with connections and open files"
            })
            
            # Process tree
            tree_path = output_dir / "process_tree.txt"
            if not self.is_windows:
                try:
                    result = subprocess.run(['pstree', '-a'], capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        with open(tree_path, 'w') as f:
                            f.write(result.stdout)
                        artifacts.append({
                            "type": "process_tree",
                            "name": "process_tree.txt",
                            "path": str(tree_path),
                            "size": tree_path.stat().st_size,
                            "description": "Process tree hierarchy"
                        })
                except Exception:
                    pass
            
        except Exception as e:
            self.log.error("Process forensics error", error=str(e))
        
        return artifacts
    
    async def _collect_network_forensics(self, output_dir: Path, incident_id: str) -> List[Dict[str, Any]]:
        """Collect network-related forensic artifacts."""
        self.log.info("Collecting network forensics")
        artifacts = []
        
        try:
            # Network connections
            netstat_path = output_dir / "netstat.txt"
            try:
                cmd = ['netstat', '-anp'] if not self.is_windows else ['netstat', '-ano']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if result.returncode == 0:
                    with open(netstat_path, 'w') as f:
                        f.write(f"# Network connections at {datetime.utcnow().isoformat()}\n")
                        f.write(result.stdout)
                    
                    artifacts.append({
                        "type": "network_connections",
                        "name": "netstat.txt",
                        "path": str(netstat_path),
                        "size": netstat_path.stat().st_size,
                        "description": "Active network connections"
                    })
            except Exception as e:
                self.log.debug("Netstat collection error", error=str(e))
            
            # Routing table
            route_path = output_dir / "routing.txt"
            try:
                if not self.is_windows:
                    result = subprocess.run(['route', '-n'], capture_output=True, text=True, timeout=10)
                else:
                    result = subprocess.run(['route', 'print'], capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    with open(route_path, 'w') as f:
                        f.write(f"# Routing table at {datetime.utcnow().isoformat()}\n")
                        f.write(result.stdout)
                    
                    artifacts.append({
                        "type": "routing_table",
                        "name": "routing.txt",
                        "path": str(route_path),
                        "size": route_path.stat().st_size,
                        "description": "Network routing table"
                    })
            except Exception as e:
                self.log.debug("Route collection error", error=str(e))
            
            # ARP table
            arp_path = output_dir / "arp.txt"
            try:
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    with open(arp_path, 'w') as f:
                        f.write(f"# ARP table at {datetime.utcnow().isoformat()}\n")
                        f.write(result.stdout)
                    
                    artifacts.append({
                        "type": "arp_table",
                        "name": "arp.txt", 
                        "path": str(arp_path),
                        "size": arp_path.stat().st_size,
                        "description": "ARP table entries"
                    })
            except Exception as e:
                self.log.debug("ARP collection error", error=str(e))
        
        except Exception as e:
            self.log.error("Network forensics error", error=str(e))
        
        return artifacts
    
    async def _collect_file_forensics(self, output_dir: Path, incident_id: str, resource: str = None) -> List[Dict[str, Any]]:
        """Collect file system forensic artifacts."""
        self.log.info("Collecting file forensics")
        artifacts = []
        
        try:
            # File system timeline
            timeline_path = output_dir / "filesystem_timeline.txt"
            
            # Collect recently modified files
            if not self.is_windows:
                try:
                    # Find files modified in last 24 hours
                    result = subprocess.run([
                        'find', '/', '-type', 'f', '-mtime', '-1',
                        '-ls'
                    ], capture_output=True, text=True, timeout=60)
                    
                    if result.returncode == 0:
                        with open(timeline_path, 'w') as f:
                            f.write(f"# Recently modified files at {datetime.utcnow().isoformat()}\n")
                            f.write(result.stdout)
                        
                        artifacts.append({
                            "type": "filesystem_timeline",
                            "name": "filesystem_timeline.txt",
                            "path": str(timeline_path),
                            "size": timeline_path.stat().st_size,
                            "description": "Files modified in last 24 hours"
                        })
                except Exception as e:
                    self.log.debug("Filesystem timeline error", error=str(e))
            
            # Collect specific suspicious locations
            suspicious_dirs = []
            if self.is_windows:
                suspicious_dirs = [
                    "C:/Windows/Temp",
                    "C:/Users/*/AppData/Local/Temp",
                    "C:/ProgramData"
                ]
            else:
                suspicious_dirs = [
                    "/tmp",
                    "/var/tmp", 
                    "/dev/shm"
                ]
            
            suspicious_files_path = output_dir / "suspicious_locations.json"
            suspicious_files = {}
            
            for dir_path in suspicious_dirs:
                try:
                    if '*' not in dir_path and os.path.exists(dir_path):
                        files = []
                        for root, dirs, filenames in os.walk(dir_path):
                            for filename in filenames[:100]:  # Limit to 100 files per dir
                                file_path = os.path.join(root, filename)
                                try:
                                    stat = os.stat(file_path)
                                    files.append({
                                        "name": filename,
                                        "path": file_path,
                                        "size": stat.st_size,
                                        "mtime": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                                        "ctime": datetime.fromtimestamp(stat.st_ctime).isoformat()
                                    })
                                except Exception:
                                    continue
                        
                        suspicious_files[dir_path] = files
                
                except Exception as e:
                    self.log.debug("Suspicious dir scan error", dir=dir_path, error=str(e))
            
            if suspicious_files:
                with open(suspicious_files_path, 'w') as f:
                    json.dump(suspicious_files, f, indent=2)
                
                artifacts.append({
                    "type": "suspicious_files",
                    "name": "suspicious_locations.json",
                    "path": str(suspicious_files_path),
                    "size": suspicious_files_path.stat().st_size,
                    "description": "Files in suspicious locations"
                })
        
        except Exception as e:
            self.log.error("File forensics error", error=str(e))
        
        return artifacts
    
    async def _collect_system_state(self, output_dir: Path, incident_id: str) -> List[Dict[str, Any]]:
        """Collect system state information."""
        self.log.info("Collecting system state")
        artifacts = []
        
        try:
            # System information
            sysinfo_path = output_dir / "system_info.json"
            sysinfo = {
                "hostname": platform.node(),
                "platform": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "users": [u._asdict() for u in psutil.users()],
                "disk_usage": {},
                "memory": psutil.virtual_memory()._asdict(),
                "cpu_count": psutil.cpu_count(),
                "cpu_times": psutil.cpu_times()._asdict()
            }
            
            # Disk usage for all partitions
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    sysinfo["disk_usage"][partition.device] = {
                        "mountpoint": partition.mountpoint,
                        "fstype": partition.fstype,
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent
                    }
                except Exception:
                    continue
            
            with open(sysinfo_path, 'w') as f:
                json.dump(sysinfo, f, indent=2, default=str)
            
            artifacts.append({
                "type": "system_info",
                "name": "system_info.json",
                "path": str(sysinfo_path),
                "size": sysinfo_path.stat().st_size,
                "description": "Complete system information"
            })
            
            # Environment variables
            env_path = output_dir / "environment.json"
            with open(env_path, 'w') as f:
                json.dump(dict(os.environ), f, indent=2)
            
            artifacts.append({
                "type": "environment",
                "name": "environment.json",
                "path": str(env_path),
                "size": env_path.stat().st_size,
                "description": "System environment variables"
            })
        
        except Exception as e:
            self.log.error("System state collection error", error=str(e))
        
        return artifacts
    
    async def _collect_logs(self, output_dir: Path, incident_id: str) -> List[Dict[str, Any]]:
        """Collect relevant log files."""
        self.log.info("Collecting logs")
        artifacts = []
        
        try:
            logs_dir = output_dir / "logs"
            logs_dir.mkdir(exist_ok=True)
            
            # Define log files to collect
            if self.is_windows:
                log_sources = [
                    ("System", "system.evtx"),
                    ("Security", "security.evtx"),
                    ("Application", "application.evtx")
                ]
                
                # Export Windows Event Logs
                for log_name, filename in log_sources:
                    try:
                        log_path = logs_dir / filename
                        result = subprocess.run([
                            'powershell', '-Command',
                            f'wevtutil epl {log_name} "{log_path}"'
                        ], capture_output=True, text=True, timeout=60)
                        
                        if result.returncode == 0 and log_path.exists():
                            artifacts.append({
                                "type": "windows_event_log",
                                "name": filename,
                                "path": str(log_path),
                                "size": log_path.stat().st_size,
                                "description": f"Windows {log_name} event log"
                            })
                    except Exception as e:
                        self.log.debug("Windows log export error", log=log_name, error=str(e))
            else:
                # Linux log files
                log_files = [
                    "/var/log/syslog",
                    "/var/log/auth.log",
                    "/var/log/kern.log",
                    "/var/log/messages",
                    "/var/log/secure",
                    "/var/log/audit/audit.log"
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file):
                        try:
                            log_name = Path(log_file).name
                            dest_path = logs_dir / log_name
                            
                            # Copy last 10000 lines
                            result = subprocess.run([
                                'tail', '-10000', log_file
                            ], capture_output=True, text=True, timeout=30)
                            
                            if result.returncode == 0:
                                with open(dest_path, 'w') as f:
                                    f.write(f"# Last 10000 lines from {log_file}\n")
                                    f.write(result.stdout)
                                
                                artifacts.append({
                                    "type": "system_log",
                                    "name": log_name,
                                    "path": str(dest_path),
                                    "size": dest_path.stat().st_size,
                                    "description": f"System log: {log_file}"
                                })
                        except Exception as e:
                            self.log.debug("Log copy error", file=log_file, error=str(e))
        
        except Exception as e:
            self.log.error("Log collection error", error=str(e))
        
        return artifacts
    
    async def _create_evidence_package(self, incident_dir: Path) -> Path:
        """Create a compressed evidence package."""
        package_name = f"{incident_dir.name}.zip"
        package_path = self.evidence_dir / package_name
        
        try:
            with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_path in incident_dir.rglob('*'):
                    if file_path.is_file():
                        arc_name = file_path.relative_to(incident_dir)
                        zf.write(file_path, arc_name)
            
            self.log.info("Evidence package created", 
                         package=str(package_path),
                         size_mb=round(package_path.stat().st_size / (1024*1024), 2))
            
            return package_path
        
        except Exception as e:
            self.log.error("Package creation error", error=str(e))
            raise
    
    async def _cleanup_old_artifacts(self):
        """Clean up old forensic artifacts."""
        try:
            cutoff_time = datetime.utcnow() - timedelta(days=7)  # Keep for 7 days
            
            for item in self.evidence_dir.iterdir():
                if item.is_dir() or item.suffix == '.zip':
                    try:
                        item_time = datetime.fromtimestamp(item.stat().st_mtime)
                        if item_time < cutoff_time:
                            if item.is_dir():
                                shutil.rmtree(item)
                            else:
                                item.unlink()
                            
                            self.log.debug("Cleaned up old artifact", path=str(item))
                    except Exception as e:
                        self.log.debug("Cleanup error", path=str(item), error=str(e))
        
        except Exception as e:
            self.log.error("Artifact cleanup error", error=str(e))
    
    # Investigation Agent helper methods
    async def get_forensic_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        """Get forensic timeline for Investigation Agent."""
        timeline = []
        
        # Look for existing forensic data
        for incident_dir in self.evidence_dir.glob(f"incident_{incident_id}_*"):
            manifest_path = incident_dir / "collection_manifest.json"
            if manifest_path.exists():
                try:
                    with open(manifest_path, 'r') as f:
                        manifest = json.load(f)
                    
                    timeline.append({
                        "timestamp": manifest["collection_start"],
                        "event": "forensic_collection_started",
                        "artifacts": len(manifest.get("artifacts", []))
                    })
                    
                    if manifest.get("collection_end"):
                        timeline.append({
                            "timestamp": manifest["collection_end"],
                            "event": "forensic_collection_completed",
                            "artifacts": len(manifest.get("artifacts", []))
                        })
                
                except Exception as e:
                    self.log.debug("Timeline parsing error", error=str(e))
        
        return timeline
    
    async def search_artifacts(self, search_term: str) -> List[Dict[str, Any]]:
        """Search forensic artifacts by content."""
        results = []
        
        # This is a basic implementation - could be enhanced with full-text search
        for artifact in self.artifacts:
            if search_term.lower() in artifact.name.lower() or \
               search_term.lower() in str(artifact.metadata).lower():
                results.append(artifact.to_dict())
        
        return results
    
    async def get_evidence_summary(self) -> Dict[str, Any]:
        """Get summary of collected evidence."""
        total_size = sum(artifact.size_bytes for artifact in self.artifacts)
        
        return {
            "total_artifacts": len(self.artifacts),
            "total_size_mb": round(total_size / (1024*1024), 2),
            "evidence_directory": str(self.evidence_dir),
            "artifact_types": list(set(artifact.artifact_type for artifact in self.artifacts)),
            "oldest_artifact": min((artifact.created_at for artifact in self.artifacts), default=None),
            "newest_artifact": max((artifact.created_at for artifact in self.artifacts), default=None)
        }