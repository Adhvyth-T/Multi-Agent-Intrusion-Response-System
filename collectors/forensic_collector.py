# collectors/forensic_collector.py (UPDATED WITH LIVE SNAPSHOT CAPABILITY)
"""
Forensic Collector - Now captures LIVE attack data immediately when triggered by Detection Agent.
This ensures rich forensic evidence is collected while the attack is still active.
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
    Enhanced Forensic Collector with LIVE ATTACK CAPTURE capability.
    
    NEW CAPABILITIES:
    - Listens to forensic_snapshot queue for immediate capture
    - Captures live attack data while malicious processes are active
    - Stores snapshots for Investigation Agent retrieval
    - Timeline reconstruction with live attack data
    - Evidence packaging with chain of custody
    """
    
    def __init__(self, evidence_dir: Optional[str] = None):
        super().__init__(name="forensic_collector")
        self.is_windows = platform.system() == "Windows"
        self.evidence_dir = Path(evidence_dir) if evidence_dir else Path(tempfile.gettempdir()) / "ir_evidence"
        self.artifacts: List[ForensicArtifact] = []
        self.collection_tasks = []
        self.live_snapshots: Dict[str, Dict[str, Any]] = {}  # Store snapshots by incident_id
        
        # Ensure evidence directory exists
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    async def start(self) -> None:
        """Start forensic collection with queue listening."""
        self.running = True
        self.start_time = datetime.utcnow()
        
        self.log.info("Forensic collector started with live snapshot capability",
                     evidence_dir=str(self.evidence_dir))
        
        # Start queue processing for immediate snapshots
        snapshot_task = asyncio.create_task(self._forensic_snapshot_loop())
        cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        self.collection_tasks.extend([snapshot_task, cleanup_task])
        
        # Wait for completion
        await asyncio.gather(*self.collection_tasks, return_exceptions=True)
    
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
    
    async def _forensic_snapshot_loop(self):
        """Process forensic_snapshot queue for immediate live capture."""
        self.log.info("Starting forensic snapshot queue processing")
        
        while self.running:
            try:
                snapshot_request = await queue.pop("forensic_snapshot", timeout=5)
                
                if snapshot_request:
                    # Process in background to avoid blocking queue
                    task = asyncio.create_task(self._process_live_snapshot(snapshot_request))
                    self.collection_tasks.append(task)
                    
            except Exception as e:
                self.log.error("Error in forensic snapshot loop", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_live_snapshot(self, request: Dict[str, Any]):
        """Process immediate live snapshot capture."""
        incident_id = request.get("incident_id")
        resource = request.get("resource")
        threat_type = request.get("threat_type")
        
        self.log.info("🔬 LIVE FORENSIC CAPTURE started", 
                     incident_id=incident_id,
                     threat_type=threat_type,
                     resource=resource)
        
        capture_start = datetime.utcnow()
        
        try:
            # Create live snapshot directory
            snapshot_dir = self.evidence_dir / f"live_snapshot_{incident_id}_{capture_start.strftime('%Y%m%d_%H%M%S')}"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            
            # Capture live attack data immediately
            live_snapshot = await self._capture_live_attack_data(
                incident_id, resource, threat_type, snapshot_dir
            )
            
            # Store for Investigation Agent retrieval
            self.live_snapshots[incident_id] = {
                **live_snapshot,
                "capture_type": "live_attack",
                "capture_time": capture_start.isoformat(),
                "snapshot_dir": str(snapshot_dir)
            }
            
            self.log.info("🔬 LIVE FORENSIC CAPTURE completed", 
                         incident_id=incident_id,
                         artifacts=len(live_snapshot.get("artifacts", [])),
                         duration_seconds=(datetime.utcnow() - capture_start).total_seconds())
            
            # Notify that live snapshot is ready
            await queue.push("notification", {
                "type": "live_forensics_captured",
                "incident_id": incident_id,
                "threat_type": threat_type,
                "artifacts": len(live_snapshot.get("artifacts", [])),
                "summary": f"Live forensic snapshot captured for {threat_type} attack"
            })
        
        except Exception as e:
            self.log.error("Live forensic capture failed", 
                          incident_id=incident_id,
                          error=str(e))
            
            # Store error info
            self.live_snapshots[incident_id] = {
                "status": "failed",
                "error": str(e),
                "capture_time": capture_start.isoformat()
            }
    
    async def _capture_live_attack_data(self, incident_id: str, resource: str, 
                                      threat_type: str, output_dir: Path) -> Dict[str, Any]:
        """Capture live attack data while processes are active."""
        
        # Live snapshot manifest
        manifest = {
            "incident_id": incident_id,
            "resource": resource,
            "threat_type": threat_type,
            "capture_start": datetime.utcnow().isoformat(),
            "capture_type": "live_attack_snapshot",
            "hostname": platform.node(),
            "platform": platform.system(),
            "artifacts": []
        }
        
        # Capture tasks - run concurrently for speed
        capture_tasks = [
            self._capture_live_processes(output_dir),
            self._capture_live_network(output_dir),
            self._capture_live_system_state(output_dir),
            self._capture_container_state(output_dir, resource)
        ]
        
        results = await asyncio.gather(*capture_tasks, return_exceptions=True)
        
        # Collect artifacts from results
        for result in results:
            if isinstance(result, list):
                manifest["artifacts"].extend(result)
            elif isinstance(result, Exception):
                self.log.error("Live capture error", error=str(result))
        
        manifest["capture_end"] = datetime.utcnow().isoformat()
        manifest["total_artifacts"] = len(manifest["artifacts"])
        
        # Save live manifest
        manifest_path = output_dir / "live_capture_manifest.json"
        with open(manifest_path, 'w') as f:
            json.dump(manifest, f, indent=2)
        
        return manifest
    
    async def _capture_live_processes(self, output_dir: Path) -> List[Dict[str, Any]]:
        """Capture live process data with active connections."""
        self.log.info("Capturing live processes")
        artifacts = []
        
        try:
            process_path = output_dir / "live_processes.json"
            processes = []
            
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe', 'cwd', 
                                           'username', 'create_time', 'cpu_times', 
                                           'memory_info', 'open_files']):
                try:
                    pinfo = proc.info
                    
                    # Get live connections for this process
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
                    
                    # Get open files
                    try:
                        pinfo['open_files'] = [f.path for f in proc.open_files()]
                    except:
                        pinfo['open_files'] = []
                    
                    # Mark if this is a suspicious process
                    if pinfo.get('cmdline'):
                        cmdline = ' '.join(pinfo['cmdline']).lower()
                        pinfo['suspicious'] = any(pattern in cmdline for pattern in [
                            'xmrig', 'minerd', 'cryptonight', 'stratum+tcp',
                            'bash -i', 'nc -e', '/dev/tcp/', 'python -c',
                            'while true', 'curl', 'wget'
                        ])
                    
                    # Convert datetime
                    if pinfo['create_time']:
                        pinfo['create_time'] = datetime.fromtimestamp(pinfo['create_time']).isoformat()
                    
                    processes.append(pinfo)
                
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
            
            with open(process_path, 'w') as f:
                json.dump(processes, f, indent=2, default=str)
            
            artifacts.append({
                "type": "live_process_snapshot",
                "name": "live_processes.json",
                "path": str(process_path),
                "size": process_path.stat().st_size,
                "description": "Live process snapshot with active connections"
            })
        
        except Exception as e:
            self.log.error("Live process capture error", error=str(e))
        
        return artifacts
    
    async def _capture_live_network(self, output_dir: Path) -> List[Dict[str, Any]]:
        """Capture live network connections and traffic."""
        self.log.info("Capturing live network state")
        artifacts = []
        
        try:
            # Active connections with more detail
            netstat_path = output_dir / "live_netstat.txt"
            cmd = ['netstat', '-antup'] if not self.is_windows else ['netstat', '-ano']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                with open(netstat_path, 'w') as f:
                    f.write(f"# LIVE network connections captured at {datetime.utcnow().isoformat()}\n")
                    f.write(result.stdout)
                
                artifacts.append({
                    "type": "live_network_connections",
                    "name": "live_netstat.txt",
                    "path": str(netstat_path),
                    "size": netstat_path.stat().st_size,
                    "description": "Live network connections during attack"
                })
            
            # Live connection summary with psutil (more detailed)
            connections_path = output_dir / "live_connections.json"
            connections = []
            
            for conn in psutil.net_connections(kind='inet'):
                try:
                    conn_info = {
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    }
                    
                    # Get process name for this connection
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            conn_info['process_name'] = proc.name()
                            conn_info['cmdline'] = proc.cmdline()
                        except:
                            pass
                    
                    connections.append(conn_info)
                
                except Exception:
                    continue
            
            with open(connections_path, 'w') as f:
                json.dump(connections, f, indent=2, default=str)
            
            artifacts.append({
                "type": "live_connection_details",
                "name": "live_connections.json", 
                "path": str(connections_path),
                "size": connections_path.stat().st_size,
                "description": "Detailed live connections with process mapping"
            })
        
        except Exception as e:
            self.log.error("Live network capture error", error=str(e))
        
        return artifacts
    
    async def _capture_live_system_state(self, output_dir: Path) -> List[Dict[str, Any]]:
        """Capture live system state during attack."""
        self.log.info("Capturing live system state")
        artifacts = []
        
        try:
            sysinfo_path = output_dir / "live_system_state.json"
            
            # Enhanced system info with live metrics
            sysinfo = {
                "hostname": platform.node(),
                "platform": platform.system(),
                "capture_time": datetime.utcnow().isoformat(),
                "uptime": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "users": [u._asdict() for u in psutil.users()],
                
                # Live resource usage
                "cpu": {
                    "percent": psutil.cpu_percent(interval=1),  # 1 second sample
                    "count": psutil.cpu_count(),
                    "times": psutil.cpu_times()._asdict()
                },
                
                "memory": psutil.virtual_memory()._asdict(),
                "swap": psutil.swap_memory()._asdict(),
                
                # Disk I/O (might show exfiltration)
                "disk_io": psutil.disk_io_counters()._asdict() if psutil.disk_io_counters() else {},
                
                # Network I/O (shows communication)
                "network_io": psutil.net_io_counters()._asdict(),
                
                # Load average (Unix)
                "load_avg": psutil.getloadavg() if hasattr(psutil, 'getloadavg') else None
            }
            
            with open(sysinfo_path, 'w') as f:
                json.dump(sysinfo, f, indent=2, default=str)
            
            artifacts.append({
                "type": "live_system_state",
                "name": "live_system_state.json",
                "path": str(sysinfo_path),
                "size": sysinfo_path.stat().st_size,
                "description": "Live system resource usage during attack"
            })
        
        except Exception as e:
            self.log.error("Live system state error", error=str(e))
        
        return artifacts
    
    async def _capture_container_state(self, output_dir: Path, resource: str) -> List[Dict[str, Any]]:
        """Capture container-specific state if applicable."""
        if not resource or "container" not in resource.lower():
            return []
        
        self.log.info("Capturing container state", resource=resource)
        artifacts = []
        
        try:
            # Extract container name
            container_name = resource.split('/')[-1] if '/' in resource else resource
            
            # Docker container inspection
            inspect_path = output_dir / "container_inspect.json"
            result = subprocess.run([
                'docker', 'inspect', container_name
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                with open(inspect_path, 'w') as f:
                    f.write(result.stdout)
                
                artifacts.append({
                    "type": "container_inspection",
                    "name": "container_inspect.json",
                    "path": str(inspect_path),
                    "size": inspect_path.stat().st_size,
                    "description": f"Docker inspection of {container_name}"
                })
            
            # Container processes
            top_path = output_dir / "container_processes.txt"
            result = subprocess.run([
                'docker', 'top', container_name
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                with open(top_path, 'w') as f:
                    f.write(f"# Live processes in {container_name} at {datetime.utcnow().isoformat()}\n")
                    f.write(result.stdout)
                
                artifacts.append({
                    "type": "container_processes",
                    "name": "container_processes.txt",
                    "path": str(top_path),
                    "size": top_path.stat().st_size,
                    "description": f"Live processes in container {container_name}"
                })
        
        except Exception as e:
            self.log.error("Container capture error", error=str(e))
        
        return artifacts
    
    async def _periodic_cleanup(self):
        """Periodic cleanup task."""
        while self.running:
            await asyncio.sleep(3600)  # Every hour
            await self._cleanup_old_artifacts()
    
    # ================================================================
    # INVESTIGATION AGENT INTERFACE
    # ================================================================
    
    async def get_live_snapshot(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Get live snapshot data for Investigation Agent."""
        return self.live_snapshots.get(incident_id)
    
    async def collect_incident_forensics(self, incident_id: str, 
                                       resource: str = None) -> Dict[str, Any]:
        """
        Enhanced forensic collection that uses live snapshot if available.
        Called by Investigation Agent.
        """
        self.log.info("Collecting forensics for investigation", incident_id=incident_id)
        
        # Check for existing live snapshot first
        live_snapshot = self.live_snapshots.get(incident_id)
        if live_snapshot and live_snapshot.get("status") != "failed":
            self.log.info("Using existing live snapshot", incident_id=incident_id)
            
            # Enhance live snapshot with additional post-incident data
            enhanced_snapshot = await self._enhance_live_snapshot(incident_id, live_snapshot, resource)
            return enhanced_snapshot
        
        # Fallback: Standard post-incident collection
        self.log.info("No live snapshot found, performing standard collection", incident_id=incident_id)
        return await self._standard_forensic_collection(incident_id, resource)
    
    async def _enhance_live_snapshot(self, incident_id: str, live_snapshot: Dict[str, Any], 
                                   resource: str) -> Dict[str, Any]:
        """Enhance live snapshot with post-incident data."""
        
        enhanced = {
            **live_snapshot,
            "enhancement_start": datetime.utcnow().isoformat(),
            "has_live_data": True,

            # FORMAT FOR IOC EXTRACTION - This is the key fix!
            "manifest": live_snapshot,  # IOC extractor looks for 'manifest'
            "artifacts": live_snapshot.get("artifacts", []),  # Ensure 'artifacts' key exists
            "artifacts_collected": len(live_snapshot.get("artifacts", [])),
        
            # Live data quality indicators
            "data_quality": "excellent",
            "capture_type": "live_attack_enhanced"
            }
        
        try:
            # Add post-incident logs
            snapshot_dir = Path(live_snapshot["snapshot_dir"])
            post_logs = await self._collect_logs(snapshot_dir / "post_incident", incident_id)
            
            enhanced["artifacts"].extend(post_logs)
            enhanced["post_incident_artifacts"] = len(post_logs)
            enhanced["enhancement_end"] = datetime.utcnow().isoformat()
            
            self.log.info("Live snapshot enhanced", 
                         incident_id=incident_id,
                         additional_artifacts=len(post_logs))
        
        except Exception as e:
            self.log.error("Snapshot enhancement failed", error=str(e))
            enhanced["enhancement_error"] = str(e)
        
        return enhanced
    
    async def _standard_forensic_collection(self, incident_id: str, resource: str) -> Dict[str, Any]:
        """Standard post-incident forensic collection (fallback)."""
        collection_start = datetime.utcnow()
        incident_dir = self.evidence_dir / f"incident_{incident_id}_{collection_start.strftime('%Y%m%d_%H%M%S')}"
        incident_dir.mkdir(parents=True, exist_ok=True)
        
        # Collection manifest
        manifest = {
            "incident_id": incident_id,
            "collection_start": collection_start.isoformat(),
            "collection_type": "post_incident",
            "has_live_data": False,
            "hostname": platform.node(),
            "platform": platform.system(),
            "resource": resource,
            "artifacts": []
        }
        
        try:
            # Standard collection tasks
            tasks = [
                self._collect_process_forensics(incident_dir, incident_id),
                self._collect_network_forensics(incident_dir, incident_id),
                self._collect_file_forensics(incident_dir, incident_id, resource),
                self._collect_system_state(incident_dir, incident_id),
                self._collect_logs(incident_dir, incident_id),
            ]
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Collect artifacts
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
            
            return {
                "status": "completed",
                "incident_id": incident_id,
                "artifacts_collected": len(manifest["artifacts"]),
                "collection_time": (datetime.utcnow() - collection_start).total_seconds(),
                "manifest": manifest,
                "has_live_data": False
            }
        
        except Exception as e:
            self.log.error("Standard forensic collection failed", error=str(e))
            return {
                "status": "failed",
                "incident_id": incident_id,
                "error": str(e),
                "has_live_data": False
            }
    
    # ================================================================
    # EXISTING METHODS (kept for compatibility)
    # ================================================================
    
    async def health_check(self) -> CollectorHealth:
        """Check collector health."""
        if not self.running:
            return CollectorHealth(
                status="unhealthy",
                message="Collector not running",
                details={}
            )
        
        try:
            # Check evidence directory
            if not self.evidence_dir.exists():
                return CollectorHealth(
                    status="unhealthy",
                    message="Evidence directory not accessible",
                    details={"evidence_dir": str(self.evidence_dir)}
                )
            
            # Check disk space
            disk_usage = psutil.disk_usage(str(self.evidence_dir))
            free_gb = disk_usage.free / (1024**3)
            
            if free_gb < 1.0:
                return CollectorHealth(
                    status="degraded",
                    message="Low disk space for evidence collection",
                    details={"free_gb": round(free_gb, 2)}
                )
            
            return CollectorHealth(
                status="healthy",
                message="Forensic collector ready with live capture",
                details={
                    "evidence_dir": str(self.evidence_dir),
                    "live_snapshots": len(self.live_snapshots),
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
        """Return enhanced collector capabilities."""
        return {
            "process_monitoring": False,
            "network_monitoring": False,
            "file_monitoring": False,
            "syscall_monitoring": False,
            "live_attack_capture": True,  # NEW
            "memory_forensics": True,
            "process_forensics": True,
            "network_forensics": True,
            "file_forensics": True,
            "log_preservation": True,
            "timeline_reconstruction": True,
            "evidence_packaging": True
        }
    
    # ================================================================
    # STANDARD FORENSIC COLLECTION METHODS (from original file)
    # ================================================================
    
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
                    
                    # Get connections separately (fixed version)
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
                    
                    # Get open files
                    try:
                        pinfo['open_files'] = [f.path for f in proc.open_files()]
                    except:
                        pinfo['open_files'] = []
                    
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