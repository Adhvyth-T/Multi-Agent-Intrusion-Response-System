# agents/investigation.py (UPDATED WITH LIVE SNAPSHOT INTEGRATION)
"""
Investigation Agent - Now uses LIVE forensic snapshots when available.
This provides rich attack data captured while the threat was active.
"""

import asyncio
import json
import uuid
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import structlog
import re

from core import queue, llm_client, save_incident, update_incident, IncidentStatus
from agents.context import context_agent

log = structlog.get_logger()


class IOCExtractor:
    """Extract Indicators of Compromise from various data sources."""
    
    # Regex patterns for IOC extraction
    IP_PATTERN = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    DOMAIN_PATTERN = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\b'
    EMAIL_PATTERN = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    HASH_PATTERNS = {
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b'
    }
    URL_PATTERN = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w.*))?)?'
    
    # Suspicious command signatures
    SUSPICIOUS_COMMANDS = [
        r'curl\s+.*\|\s*bash',
        r'wget\s+.*\|\s*sh',
        r'powershell\s+.*-enc\s+',
        r'bash\s+-i\s+>&',
        r'nc\s+.*-e\s+',
        r'python\s+.*-c\s+.*socket',
        r'perl\s+.*-e\s+.*socket',
        r'/bin/sh.*>&',
        r'cmd\.exe.*>&'
    ]
    
    def extract_from_text(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text content."""
        iocs = {
            'ips': [],
            'domains': [],
            'emails': [],
            'urls': [],
            'hashes': {'md5': [], 'sha1': [], 'sha256': []},
            'suspicious_commands': []
        }
        
        if not text:
            return iocs
        
        # Extract IPs
        ips = re.findall(self.IP_PATTERN, text)
        iocs['ips'] = self._filter_private_ips(list(set(ips)))
        
        # Extract domains
        domains = re.findall(self.DOMAIN_PATTERN, text, re.IGNORECASE)
        iocs['domains'] = self._filter_domains(list(set(domains)))
        
        # Extract emails
        emails = re.findall(self.EMAIL_PATTERN, text)
        iocs['emails'] = list(set(emails))
        
        # Extract URLs
        urls = re.findall(self.URL_PATTERN, text)
        iocs['urls'] = list(set(urls))
        
        # Extract hashes
        for hash_type, pattern in self.HASH_PATTERNS.items():
            hashes = re.findall(pattern, text)
            iocs['hashes'][hash_type] = list(set(hashes))
        
        # Extract suspicious commands
        for pattern in self.SUSPICIOUS_COMMANDS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            iocs['suspicious_commands'].extend(matches)
        
        iocs['suspicious_commands'] = list(set(iocs['suspicious_commands']))
        
        return iocs
    
    def _filter_private_ips(self, ips: List[str]) -> List[str]:
        """Filter out private/local IP addresses."""
        filtered = []
        private_ranges = [
            r'^10\.',
            r'^172\.(1[6-9]|2[0-9]|3[01])\.',
            r'^192\.168\.',
            r'^127\.',
            r'^169\.254\.',
            r'^::1$',
            r'^0\.0\.0\.0$',
            r'^255\.255\.255\.255$'
        ]
        
        for ip in ips:
            is_private = False
            for pattern in private_ranges:
                if re.match(pattern, ip):
                    is_private = True
                    break
            if not is_private:
                filtered.append(ip)
        
        return filtered
    
    def _filter_domains(self, domains: List[str]) -> List[str]:
        """Filter out local/common domains."""
        filtered = []
        skip_domains = [
            'localhost', 'local', 'example.com', 'test.com',
            'docker.internal', 'kubernetes.local'
        ]
        
        for domain in domains:
            if (len(domain) > 3 and 
                '.' in domain and 
                domain.lower() not in skip_domains and
                not domain.replace('.', '').isdigit()):  # Skip IP-like strings
                filtered.append(domain)
        
        return filtered
    
    def extract_from_forensic_data(self, forensic_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from complete forensic package."""
        all_iocs = {
            'ips': set(),
            'domains': set(),
            'emails': set(),
            'urls': set(),
            'hashes': {'md5': set(), 'sha1': set(), 'sha256': set()},
            'suspicious_commands': set()
        }
        
        # Extract from manifest
        manifest = forensic_data.get('manifest', {})
        if manifest:
            manifest_text = json.dumps(manifest)
            manifest_iocs = self.extract_from_text(manifest_text)
            self._merge_iocs(all_iocs, manifest_iocs)
        
        # Extract from artifacts - NOW READS FILE CONTENTS!
        artifacts = forensic_data.get('artifacts', [])
        for artifact in artifacts:
            if isinstance(artifact, dict):
                # Extract IOCs from artifact metadata
                artifact_text = json.dumps(artifact)
                artifact_iocs = self.extract_from_text(artifact_text)
                self._merge_iocs(all_iocs, artifact_iocs)
                
                # NEW: Extract IOCs from actual file contents
                file_path = artifact.get('path')
                if file_path and os.path.exists(file_path):
                    try:
                        # Read file content based on type
                        file_content = self._read_artifact_file(file_path, artifact.get('type', ''))
                        if file_content:
                            file_iocs = self.extract_from_text(file_content)
                            self._merge_iocs(all_iocs, file_iocs)
                    except Exception as e:
                        # Log error but continue processing other artifacts
                        pass
        
        # Convert sets back to lists
        result = {
            'ips': list(all_iocs['ips']),
            'domains': list(all_iocs['domains']),
            'emails': list(all_iocs['emails']),
            'urls': list(all_iocs['urls']),
            'hashes': {
                'md5': list(all_iocs['hashes']['md5']),
                'sha1': list(all_iocs['hashes']['sha1']),
                'sha256': list(all_iocs['hashes']['sha256'])
            },
            'suspicious_commands': list(all_iocs['suspicious_commands'])
        }
        
        return result
    
    def _read_artifact_file(self, file_path: str, artifact_type: str) -> str:
        """Read artifact file content for IOC extraction."""
        try:
            # Different handling based on file type
            if artifact_type in ['live_process_snapshot', 'process_snapshot', 
                               'live_connection_details', 'live_system_state',
                               'container_inspection', 'system_info']:
                # JSON files - read and extract
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return content
                
            elif artifact_type in ['live_network_connections', 'network_connections',
                                 'container_processes', 'process_tree']:
                # Text files - read directly
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                return content
                
            elif 'log' in artifact_type.lower():
                # Log files - read with size limit
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read(50000)  # Read first 50KB
                return content
                
            else:
                # Try to read as text with fallback
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read(10000)  # Read first 10KB
                    return content
                except UnicodeDecodeError:
                    # Skip binary files
                    return ""
                    
        except Exception as e:
            return ""
    
    def _merge_iocs(self, target: Dict, source: Dict):
        """Merge IOCs from source into target."""
        for key in ['ips', 'domains', 'emails', 'urls', 'suspicious_commands']:
            if key in source:
                target[key].update(source[key])
        
        for hash_type in ['md5', 'sha1', 'sha256']:
            if hash_type in source.get('hashes', {}):
                target['hashes'][hash_type].update(source['hashes'][hash_type])


class TimelineReconstructor:
    """Reconstruct timeline of events from various sources."""
    
    def __init__(self):
        self.events = []
    
    def add_forensic_timeline(self, forensic_data: Dict[str, Any]):
        """Add events from forensic collection."""
        manifest = forensic_data.get('manifest', {})
        
        # Collection timestamps
        if manifest.get('collection_start') or manifest.get('capture_start'):
            start_time = manifest.get('capture_start') or manifest.get('collection_start')
            capture_type = manifest.get('capture_type', 'forensic_collection')
            
            self.events.append({
                'timestamp': start_time,
                'source': 'forensic_collector',
                'event_type': 'forensic_collection_started',
                'description': f"Forensic evidence collection began for incident {manifest.get('incident_id', 'unknown')} ({capture_type})",
                'details': {
                    'artifacts': len(manifest.get('artifacts', [])),
                    'capture_type': capture_type,
                    'has_live_data': manifest.get('has_live_data', False)
                }
            })
        
        if manifest.get('collection_end') or manifest.get('capture_end'):
            end_time = manifest.get('capture_end') or manifest.get('collection_end')
            
            self.events.append({
                'timestamp': end_time,
                'source': 'forensic_collector',
                'event_type': 'forensic_collection_completed',
                'description': f"Forensic evidence collection completed with {len(manifest.get('artifacts', []))} artifacts",
                'details': manifest
            })
    
    def add_log_timeline(self, log_data: List[Dict[str, Any]]):
        """Add events from log analysis."""
        for log_entry in log_data:
            if isinstance(log_entry, dict) and 'timestamp' in log_entry:
                self.events.append({
                    'timestamp': log_entry['timestamp'],
                    'source': log_entry.get('source', 'logs'),
                    'event_type': 'log_event',
                    'description': log_entry.get('message', 'Log entry'),
                    'details': log_entry
                })
    
    def add_network_timeline(self, network_data: List[Dict[str, Any]]):
        """Add events from network analysis."""
        for connection in network_data:
            if isinstance(connection, dict) and 'timestamp' in connection:
                self.events.append({
                    'timestamp': connection['timestamp'],
                    'source': 'network_collector',
                    'event_type': 'network_connection',
                    'description': f"Network connection: {connection.get('local_addr')}:{connection.get('local_port')} -> {connection.get('remote_addr')}:{connection.get('remote_port')}",
                    'details': connection
                })
    
    def add_incident_timeline(self, incident: Dict[str, Any]):
        """Add incident creation event."""
        if incident.get('created_at'):
            self.events.append({
                'timestamp': incident['created_at'],
                'source': 'detection_agent',
                'event_type': 'incident_detected',
                'description': f"Incident detected: {incident.get('type', 'unknown')} on {incident.get('resource', 'unknown')}",
                'details': incident
            })
    
    def build_timeline(self) -> List[Dict[str, Any]]:
        """Build chronological timeline of all events."""
        # Sort by timestamp
        sorted_events = sorted(
            self.events,
            key=lambda x: datetime.fromisoformat(x['timestamp'].replace('Z', '+00:00')) if isinstance(x['timestamp'], str) else x['timestamp']
        )
        
        # Add sequence numbers
        for i, event in enumerate(sorted_events):
            event['sequence'] = i + 1
        
        return sorted_events


class LateralMovementAnalyzer:
    """Analyze potential lateral movement patterns."""
    
    def __init__(self):
        self.suspicious_patterns = []
    
    def analyze_network_connections(self, connections: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze network connections for lateral movement indicators."""
        analysis = {
            'suspicious_connections': [],
            'internal_scanning': [],
            'unusual_ports': [],
            'multiple_targets': [],
            'risk_score': 0
        }
        
        if not connections:
            return analysis
        
        # Group connections by source
        connection_groups = {}
        for conn in connections:
            source = conn.get('local_addr', 'unknown')
            if source not in connection_groups:
                connection_groups[source] = []
            connection_groups[source].append(conn)
        
        # Analyze each source
        for source, conns in connection_groups.items():
            # Check for multiple targets (potential scanning)
            unique_targets = set()
            unusual_ports = []
            
            for conn in conns:
                remote_addr = conn.get('remote_addr')
                remote_port = conn.get('remote_port')
                
                if remote_addr:
                    unique_targets.add(remote_addr)
                
                # Check for unusual ports
                if remote_port and remote_port in [22, 23, 3389, 5985, 5986]:  # SSH, Telnet, RDP, WinRM
                    unusual_ports.append({
                        'port': remote_port,
                        'target': remote_addr,
                        'protocol': conn.get('protocol', 'unknown')
                    })
            
            # Multiple targets from same source
            if len(unique_targets) > 5:
                analysis['multiple_targets'].append({
                    'source': source,
                    'target_count': len(unique_targets),
                    'targets': list(unique_targets)[:10]  # Limit for display
                })
                analysis['risk_score'] += 3
            
            # Unusual administrative ports
            if unusual_ports:
                analysis['unusual_ports'].extend(unusual_ports)
                analysis['risk_score'] += len(unusual_ports)
        
        return analysis
    
    def analyze_authentication_patterns(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze authentication logs for lateral movement."""
        analysis = {
            'failed_authentications': [],
            'unusual_login_patterns': [],
            'privilege_escalation_attempts': [],
            'risk_score': 0
        }
        
        auth_patterns = [
            r'authentication\s+(failed|failure)',
            r'login\s+(failed|failure)',
            r'invalid\s+(user|login)',
            r'sudo.*failed',
            r'su.*failed'
        ]
        
        for log_entry in logs:
            message = log_entry.get('message', '').lower()
            
            for pattern in auth_patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    analysis['failed_authentications'].append({
                        'timestamp': log_entry.get('timestamp'),
                        'source': log_entry.get('source', 'unknown'),
                        'message': log_entry.get('message', '')[:200]
                    })
                    analysis['risk_score'] += 1
                    break
        
        return analysis


class InvestigationAgent:
    """Investigation Agent - uses Context Agent for all incident data."""
    
    def __init__(self):
        self.running = False
        self.ioc_extractor = IOCExtractor()
        self.investigation_count = 0
        self.success_count = 0
        
        log.info("Investigation Agent initialized")
    
    async def start(self):
        """Start the investigation agent."""
        self.running = True
        log.info("Investigation Agent started")
        await self._investigation_loop()
    
    async def stop(self):
        """Stop the investigation agent."""
        self.running = False
        log.info("Investigation Agent stopped",
                total_investigations=self.investigation_count,
                successful=self.success_count)
    
    async def _investigation_loop(self):
        """Main investigation processing loop."""
        while self.running:
            try:
                investigation_request = await queue.pop("investigation", timeout=5)
                
                if investigation_request:
                    await self._process_investigation(investigation_request)
            except Exception as e:
                log.error("Error in investigation loop", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_investigation(self, request: Dict[str, Any]):
        """Process a single investigation request using full context from Context Agent."""
        incident_id = request.get("incident_id")
        
        log.info("Starting investigation", incident_id=incident_id)
        self.investigation_count += 1
        investigation_start = datetime.utcnow()
        
        try:
            # 1. Pull everything from Context Agent - forensics, enriched triage,
            #    reasoning chain, actions, validation results - all in one call.
            context = await context_agent.get_context_for_investigation(incident_id)
            
            incident      = context["incident"]
            forensic_data = context["forensic_snapshot"]
            has_live_data = context["has_live_forensics"]
            enriched      = context["enriched"]
            
            log.info("Context loaded",
                     incident_id=incident_id,
                     has_live_forensics=has_live_data,
                     artifacts=len(forensic_data.get("artifacts", [])),
                     actions_taken=len(context["actions"]))
            
            # 2. Extract log + network analysis directly from forensic artifact files
            #    already captured by the ForensicCollector - no new collection needed.
            log_analysis     = self._extract_logs_from_context(context)
            network_analysis = self._extract_network_from_context(context)
            
            # 3. Reconstruct timeline
            timeline = self._reconstruct_timeline(incident, forensic_data, log_analysis, network_analysis)
            
            # 4. Extract IOCs
            iocs = await self._extract_iocs(forensic_data, log_analysis, network_analysis)
            
            # 5. Lateral movement analysis
            lateral_movement = self._analyze_lateral_movement(network_analysis, log_analysis)
            
            # 6. LLM root cause - now receives full context including reasoning chain,
            #    enriched triage, containment actions and validation results.
            root_cause = await self._perform_root_cause_analysis(
                context, timeline, iocs, lateral_movement
            )
            
            # 7. Generate report
            investigation_report = self._generate_investigation_report(
                incident_id=incident_id,
                forensic_data=forensic_data,
                log_analysis=log_analysis,
                network_analysis=network_analysis,
                host_analysis={},   # no longer collected separately
                timeline=timeline,
                iocs=iocs,
                lateral_movement=lateral_movement,
                root_cause=root_cause,
                duration=(datetime.utcnow() - investigation_start).total_seconds(),
                has_live_data=has_live_data
            )
            
            # 8. Persist + annotate context
            await self._save_investigation_report(incident_id, investigation_report)
            context_agent.update_context(incident_id, "investigation", {
                "root_cause_summary": root_cause.get("summary"),
                "iocs_found": len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
                "timeline_events": len(timeline),
                "confidence": root_cause.get("confidence", 0.0),
            })
            
            await update_incident(incident_id, {"status": IncidentStatus.RECOVERING.value})
            
            # 9. Push to recovery queue
            await queue.push("recovery", {
                "incident_id": incident_id,
                "investigation_id": investigation_report["id"],
                "root_cause": root_cause,
                "recommendations": root_cause.get("recommendations", []),
                "iocs": iocs,
                "timeline": timeline[-5:],
                "severity": incident.get("severity", "P3"),
                "has_live_data": has_live_data
            })
            
            await queue.push("notification", {
                "type": "investigation_complete",
                "incident_id": incident_id,
                "severity": incident.get("severity", "P3"),
                "iocs_found": len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
                "timeline_events": len(timeline),
                "root_cause": root_cause.get("summary", "Investigation completed"),
                "recommendations": len(root_cause.get("recommendations", [])),
                "duration_seconds": investigation_report["duration_seconds"],
                "has_live_data": has_live_data,
                "data_quality": "excellent" if has_live_data else "good"
            })
            
            self.success_count += 1
            log.info("Investigation completed",
                    incident_id=incident_id,
                    duration_seconds=investigation_report["duration_seconds"],
                    iocs_found=len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
                    timeline_events=len(timeline),
                    has_live_data=has_live_data)
            
        except Exception as e:
            log.error("Investigation failed", incident_id=incident_id, error=str(e), exc_info=True)
            await queue.push("notification", {
                "type": "investigation_error",
                "incident_id": incident_id,
                "severity": "P2",
                "error": str(e),
                "summary": f"Investigation failed: {str(e)}"
            })
    
    def _extract_logs_from_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract log data from forensic artifact files already stored in context.
        Reads shell_history artifacts and any log-type artifacts on disk.
        """
        logs = []
        suspicious_patterns = []
        threat_keywords = [
            'error', 'exception', 'fail', 'attack', 'malware',
            'unauthorized', 'denied', 'blocked', 'suspicious'
        ]

        artifacts = context.get("forensic_snapshot", {}).get("artifacts", [])
        for artifact in artifacts:
            artifact_type = artifact.get("type", "")
            file_path = artifact.get("path", "")

            # Only read log-like artifacts
            if not any(t in artifact_type for t in ['log', 'shell_history']):
                continue

            if not file_path or not os.path.exists(file_path):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(50000)  # cap at 50KB

                # Turn each non-empty line into a log entry
                for line in content.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    entry = {
                        "message": line,
                        "source": artifact_type,
                        "timestamp": artifact.get("captured_at", context["assembled_at"])
                    }
                    logs.append(entry)

                    # Flag suspicious lines
                    if any(kw in line.lower() for kw in threat_keywords):
                        suspicious_patterns.append({
                            "pattern": next(kw for kw in threat_keywords if kw in line.lower()),
                            "line": line,
                            "source": artifact_type
                        })

            except Exception as e:
                log.debug("Could not read artifact file", path=file_path, error=str(e))

        log.info("Log extraction from context complete",
                 total_logs=len(logs), suspicious=len(suspicious_patterns))
        return {
            "logs": logs,
            "suspicious_patterns": suspicious_patterns,
            "total_logs_analyzed": len(logs)
        }

    def _extract_network_from_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract network connection data from forensic artifact files already in context.
        Reads live_network_connections / live_connection_details artifacts.
        """
        connections = []
        unique_destinations: set = set()

        artifacts = context.get("forensic_snapshot", {}).get("artifacts", [])
        for artifact in artifacts:
            artifact_type = artifact.get("type", "")
            file_path = artifact.get("path", "")

            if not any(t in artifact_type for t in ['network', 'connection', 'netstat']):
                continue

            if not file_path or not os.path.exists(file_path):
                continue

            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # JSON artifacts (live_connections.json)
                if file_path.endswith('.json'):
                    data = json.loads(content)
                    if isinstance(data, list):
                        for conn in data:
                            connections.append(conn)
                            raddr = conn.get('raddr') or conn.get('remote_addr')
                            if raddr:
                                unique_destinations.add(raddr)
                else:
                    # Plain text netstat - parse lines
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        connections.append({"raw": line, "source": "netstat"})

            except Exception as e:
                log.debug("Could not read network artifact", path=file_path, error=str(e))

        log.info("Network extraction from context complete",
                 total_connections=len(connections),
                 unique_destinations=len(unique_destinations))
        return {
            "connections": connections,
            "summary": {"unique_destinations": len(unique_destinations)},
            "total_connections": len(connections)
        }
    
    async def _perform_root_cause_analysis(self,
                                          context: Dict[str, Any],
                                          timeline: List[Dict[str, Any]],
                                          iocs: Dict[str, Any],
                                          lateral_movement: Dict[str, Any]) -> Dict[str, Any]:
        """
        Root cause analysis using the full incident context assembled by Context Agent.
        Receives reasoning chain, enriched triage, containment actions and validation
        results - significantly richer than what collector-based analysis could provide.
        """
        incident     = context["incident"]
        enriched     = context["enriched"]
        forensic_data = context["forensic_snapshot"]
        has_live_data = context["has_live_forensics"]

        log.info("Performing root cause analysis",
                 incident_id=incident.get("id"),
                 has_live_data=has_live_data)
        
        try:
            llm_context = {
                # Core incident info
                "incident": incident,
                "severity": incident.get("severity"),
                "incident_type": incident.get("type"),
                "resource": incident.get("resource"),
                "mitre_mapping": context.get("mitre_mapping", {}),
                "asset_criticality": context.get("asset_criticality", {}),

                # Triage intelligence
                "triage": {
                    "confidence": enriched.get("confidence"),
                    "llm_summary": enriched.get("llm_summary"),
                    "recommended_actions": enriched.get("recommended_actions", []),
                },

                # LLM reasoning steps from triage
                "reasoning_chain": context.get("reasoning_chain", []),

                # What containment was attempted and how it went
                "containment_summary": context.get("containment_summary", {}),
                "retry_history": context.get("retry_history", []),

                # Forensic evidence quality
                "forensic_summary": {
                    "has_live_data": has_live_data,
                    "artifacts_collected": len(forensic_data.get("artifacts", [])),
                    "data_quality": "excellent" if has_live_data else "standard",
                },

                # Derived signals
                "iocs_found": {
                    "ips": len(iocs.get("ips", [])),
                    "domains": len(iocs.get("domains", [])),
                    "commands": len(iocs.get("suspicious_commands", [])),
                    "top_ips": iocs.get("ips", [])[:5],
                    "top_domains": iocs.get("domains", [])[:5],
                    "top_commands": iocs.get("suspicious_commands", [])[:3],
                },
                "lateral_movement_risk": lateral_movement.get("overall_risk_score", 0),
                "key_timeline_events": timeline[-10:] if timeline else [],
                "timeline_events": len(timeline),

                # Phase updates from other agents (triage summary, containment outcome, etc.)
                "phase_updates": context.get("phase_updates", {}),
            }
            
            root_cause_analysis = await llm_client.analyze_incident_root_cause(
                incident=incident,
                context=llm_context
            )
            
            root_cause_analysis["data_quality"] = "excellent" if has_live_data else "standard"
            root_cause_analysis["analysis_note"] = (
                "Analysis based on live attack data and full pipeline context"
                if has_live_data else
                "Analysis based on post-incident forensics and full pipeline context"
            )
            
            log.info("Root cause analysis completed",
                    confidence=root_cause_analysis.get("confidence", 0))
            
            return root_cause_analysis
        
        except Exception as e:
            log.error("Root cause analysis failed", error=str(e))
            return {
                "summary": f"Automated analysis for incident {incident.get('id', 'unknown')}",
                "attack_vector": "Unknown - Analysis failed",
                "confidence": 0.5 if has_live_data else 0.3,
                "data_quality": "excellent" if has_live_data else "standard",
                "recommendations": [
                    "Review forensic evidence manually",
                    "Investigate suspicious IOCs found",
                    "Monitor for lateral movement indicators"
                ],
                "error": str(e),
            }
    
    def _generate_investigation_report(self, **kwargs) -> Dict[str, Any]:
        """Generate enhanced investigation report with live data indicators."""
        report_id = str(uuid.uuid4())[:8]
        
        report = {
            "id": report_id,
            "incident_id": kwargs["incident_id"],
            "generated_at": datetime.utcnow().isoformat(),
            "duration_seconds": kwargs["duration"],
            "has_live_data": kwargs.get("has_live_data", False),
            "data_quality": "excellent" if kwargs.get("has_live_data", False) else "good",
            "forensic_evidence": kwargs["forensic_data"],
            "log_analysis": kwargs["log_analysis"],
            "network_analysis": kwargs["network_analysis"],
            "host_analysis": kwargs["host_analysis"],
            "timeline": kwargs["timeline"],
            "iocs": kwargs["iocs"],
            "lateral_movement": kwargs["lateral_movement"],
            "root_cause": kwargs["root_cause"],
            "summary": {
                "total_artifacts": kwargs["forensic_data"].get("artifacts_collected", 0),
                "total_logs_analyzed": kwargs["log_analysis"].get("total_logs_analyzed", 0),
                "total_connections": kwargs["network_analysis"].get("total_connections", 0),
                "timeline_events": len(kwargs["timeline"]),
                "total_iocs": (len(kwargs["iocs"].get("ips", [])) + 
                              len(kwargs["iocs"].get("domains", [])) + 
                              len(kwargs["iocs"].get("suspicious_commands", []))),
                "lateral_movement_risk": kwargs["lateral_movement"].get("overall_risk_score", 0),
                "root_cause_confidence": kwargs["root_cause"].get("confidence", 0.0),
                "live_attack_captured": kwargs.get("has_live_data", False)
            }
        }
        
        return report
    
    def get_stats(self) -> Dict[str, Any]:
        """Get investigation agent statistics."""
        return {
            "total_investigations": self.investigation_count,
            "successful_investigations": self.success_count,
            "success_rate": (
                self.success_count / self.investigation_count
                if self.investigation_count > 0 else 0
            ),
        }
    
    
    def _reconstruct_timeline(self, incident: Dict[str, Any],
                              forensic_data: Dict[str, Any],
                              log_analysis: Dict[str, Any],
                              network_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Reconstruct timeline of events."""
        log.info("Reconstructing timeline")
        
        reconstructor = TimelineReconstructor()
        reconstructor.add_incident_timeline(incident)
        reconstructor.add_forensic_timeline(forensic_data)
        
        # Add log events
        logs = log_analysis.get("logs", [])
        reconstructor.add_log_timeline(logs[-50:])  # Last 50 log entries
        
        # Add network events
        connections = network_analysis.get("connections", [])
        reconstructor.add_network_timeline(connections[-20:])  # Last 20 connections
        
        timeline = reconstructor.build_timeline()
        
        log.info("Timeline reconstructed", events=len(timeline))
        return timeline
    
    async def _extract_iocs(self, forensic_data: Dict[str, Any],
                           log_analysis: Dict[str, Any],
                           network_analysis: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract Indicators of Compromise from all sources."""
        log.info("Extracting IOCs")
        
        # Extract from forensic data
        forensic_iocs = self.ioc_extractor.extract_from_forensic_data(forensic_data)
        
        # Extract from logs
        log_iocs = {'ips': set(), 'domains': set(), 'emails': set(), 'urls': set(), 
                   'hashes': {'md5': set(), 'sha1': set(), 'sha256': set()}, 'suspicious_commands': set()}
        
        for log_entry in log_analysis.get("logs", []):
            if isinstance(log_entry, dict):
                message = log_entry.get("message", "")
                entry_iocs = self.ioc_extractor.extract_from_text(message)
                
                # Merge IOCs
                for key in ['ips', 'domains', 'emails', 'urls', 'suspicious_commands']:
                    log_iocs[key].update(entry_iocs.get(key, []))
                
                for hash_type in ['md5', 'sha1', 'sha256']:
                    log_iocs['hashes'][hash_type].update(entry_iocs.get('hashes', {}).get(hash_type, []))
        
        # Merge all IOCs
        all_iocs = {
            'ips': list(set(forensic_iocs.get('ips', []) + list(log_iocs['ips']))),
            'domains': list(set(forensic_iocs.get('domains', []) + list(log_iocs['domains']))),
            'emails': list(set(forensic_iocs.get('emails', []) + list(log_iocs['emails']))),
            'urls': list(set(forensic_iocs.get('urls', []) + list(log_iocs['urls']))),
            'hashes': {
                'md5': list(set(forensic_iocs.get('hashes', {}).get('md5', []) + list(log_iocs['hashes']['md5']))),
                'sha1': list(set(forensic_iocs.get('hashes', {}).get('sha1', []) + list(log_iocs['hashes']['sha1']))),
                'sha256': list(set(forensic_iocs.get('hashes', {}).get('sha256', []) + list(log_iocs['hashes']['sha256'])))
            },
            'suspicious_commands': list(set(forensic_iocs.get('suspicious_commands', []) + list(log_iocs['suspicious_commands'])))
        }
        
        total_iocs = (len(all_iocs['ips']) + len(all_iocs['domains']) + 
                     len(all_iocs['suspicious_commands']))
        
        log.info("IOC extraction completed", total_iocs=total_iocs)
        return all_iocs
    
    def _analyze_lateral_movement(self, network_analysis: Dict[str, Any],
                                       log_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze potential lateral movement."""
        log.info("Analyzing lateral movement")
        
        analyzer = LateralMovementAnalyzer()
        
        # Analyze network connections
        connections = network_analysis.get("connections", [])
        network_lateral = analyzer.analyze_network_connections(connections)
        
        # Analyze authentication patterns
        logs = log_analysis.get("logs", [])
        auth_lateral = analyzer.analyze_authentication_patterns(logs)
        
        # Combine analysis
        lateral_analysis = {
            "network_analysis": network_lateral,
            "authentication_analysis": auth_lateral,
            "overall_risk_score": network_lateral.get("risk_score", 0) + auth_lateral.get("risk_score", 0),
            "indicators_found": []
        }
        
        # Add indicators based on analysis
        if network_lateral.get("multiple_targets"):
            lateral_analysis["indicators_found"].append("Multiple target scanning detected")
        
        if network_lateral.get("unusual_ports"):
            lateral_analysis["indicators_found"].append("Administrative port access detected")
        
        if auth_lateral.get("failed_authentications"):
            lateral_analysis["indicators_found"].append("Multiple authentication failures detected")
        
        log.info("Lateral movement analysis completed",
                risk_score=lateral_analysis["overall_risk_score"],
                indicators=len(lateral_analysis["indicators_found"]))
        
        return lateral_analysis
    
    async def _save_investigation_report(self, incident_id: str, report: Dict[str, Any]):
        """Save investigation report to database."""
        try:
            # For now, we'll save as a JSON field in the incidents table
            # In production, you'd have a dedicated investigations table
            await update_incident(incident_id, {
                "investigation_report": json.dumps(report),
                "status": IncidentStatus.INVESTIGATING.value
            })
            
            log.info("Investigation report saved", 
                    incident_id=incident_id,
                    report_id=report["id"])
        
        except Exception as e:
            log.error("Failed to save investigation report", error=str(e))


# Agent instance
investigation_agent = InvestigationAgent()