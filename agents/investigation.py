# agents/investigation.py
"""
Investigation Agent - Week 3, Days 6-7
Forensic analysis, root cause identification, IOC extraction, lateral movement detection.

Integrates with the comprehensive collector system for complete investigation capabilities.
"""

import asyncio
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import structlog
import re

from core import queue, llm_client, save_incident, update_incident, IncidentStatus
from collectors import CollectorManager, CollectorFactory, ForensicCollector, LogCollector, NetworkCollector, HostCollector
from config import config

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
        
        # Extract from artifacts
        artifacts = forensic_data.get('artifacts', [])
        for artifact in artifacts:
            if isinstance(artifact, dict):
                artifact_text = json.dumps(artifact)
                artifact_iocs = self.extract_from_text(artifact_text)
                self._merge_iocs(all_iocs, artifact_iocs)
        
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
        if manifest.get('collection_start'):
            self.events.append({
                'timestamp': manifest['collection_start'],
                'source': 'forensic_collector',
                'event_type': 'forensic_collection_started',
                'description': f"Forensic evidence collection began for incident {manifest.get('incident_id', 'unknown')}",
                'details': {'artifacts': len(manifest.get('artifacts', []))}
            })
        
        if manifest.get('collection_end'):
            self.events.append({
                'timestamp': manifest['collection_end'],
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
    """Main Investigation Agent that performs comprehensive forensic analysis."""
    
    def __init__(self):
        self.running = False
        self.collector_manager = None
        self.ioc_extractor = IOCExtractor()
        self.investigation_count = 0
        self.success_count = 0
        
        log.info("Investigation Agent initialized")
    
    async def start(self):
        """Start the investigation agent."""
        self.running = True
        
        # Initialize collectors for investigation
        log.info("Setting up investigation collectors...")
        await self._setup_collectors()
        
        log.info("Investigation Agent started with comprehensive forensic capabilities")
        await self._investigation_loop()
    
    async def stop(self):
        """Stop the investigation agent."""
        self.running = False
        
        if self.collector_manager:
            await self.collector_manager.stop_all()
        
        log.info("Investigation Agent stopped",
                total_investigations=self.investigation_count,
                successful=self.success_count)
    
    async def _setup_collectors(self):
        """Set up collectors needed for investigation."""
        try:
            # Create investigation collectors
            investigation_collectors = await CollectorFactory.create_investigation_collectors(
                collectors=['log', 'network', 'host', 'forensic'],
                evidence_dir="./evidence"
            )
            
            # Set up collector manager
            self.collector_manager = CollectorManager()
            
            # Add investigation collectors
            for collector in investigation_collectors:
                await self.collector_manager.add_collector(collector.name, collector)
            
            log.info("Investigation collectors ready",
                    count=len(investigation_collectors))
            
        except Exception as e:
            log.error("Failed to setup investigation collectors", error=str(e))
            raise
    
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
        """Process a single investigation request."""
        incident_id = request.get("incident_id")
        resource = request.get("resource", "unknown")
        
        log.info("Starting investigation",
                incident_id=incident_id,
                resource=resource)
        
        self.investigation_count += 1
        investigation_start = datetime.utcnow()
        
        try:
            # 1. Collect forensic evidence
            forensic_data = await self._collect_forensic_evidence(incident_id, resource)
            
            # 2. Analyze logs
            log_analysis = await self._analyze_logs(incident_id, resource)
            
            # 3. Analyze network activity
            network_analysis = await self._analyze_network_activity(incident_id)
            
            # 4. Analyze host state
            host_analysis = await self._analyze_host_state(incident_id)
            
            # 5. Reconstruct timeline
            timeline = await self._reconstruct_timeline(
                request, forensic_data, log_analysis, network_analysis
            )
            
            # 6. Extract IOCs
            iocs = await self._extract_iocs(forensic_data, log_analysis, network_analysis)
            
            # 7. Analyze lateral movement
            lateral_movement = await self._analyze_lateral_movement(network_analysis, log_analysis)
            
            # 8. LLM-powered root cause analysis
            root_cause = await self._perform_root_cause_analysis(
                request, forensic_data, log_analysis, network_analysis, 
                timeline, iocs, lateral_movement
            )
            
            # 9. Generate investigation report
            investigation_report = self._generate_investigation_report(
                incident_id=incident_id,
                forensic_data=forensic_data,
                log_analysis=log_analysis,
                network_analysis=network_analysis,
                host_analysis=host_analysis,
                timeline=timeline,
                iocs=iocs,
                lateral_movement=lateral_movement,
                root_cause=root_cause,
                duration=(datetime.utcnow() - investigation_start).total_seconds()
            )
            
            # 10. Save investigation results
            await self._save_investigation_report(incident_id, investigation_report)
            
            # 11. Update incident status
            await update_incident(incident_id, {
                "status": IncidentStatus.RECOVERING.value
            })
            
            # 12. Push to recovery queue
            await queue.push("recovery", {
                "incident_id": incident_id,
                "investigation_id": investigation_report["id"],
                "root_cause": root_cause,
                "recommendations": root_cause.get("recommendations", []),
                "iocs": iocs,
                "timeline": timeline[-5:],  # Last 5 events for context
                "severity": request.get("severity", "P3")
            })
            
            # 13. Send notification
            await queue.push("notification", {
                "type": "investigation_complete",
                "incident_id": incident_id,
                "severity": request.get("severity", "P3"),
                "iocs_found": len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
                "timeline_events": len(timeline),
                "root_cause": root_cause.get("summary", "Investigation completed"),
                "recommendations": len(root_cause.get("recommendations", [])),
                "duration_seconds": investigation_report["duration_seconds"]
            })
            
            self.success_count += 1
            log.info("Investigation completed successfully",
                    incident_id=incident_id,
                    duration_seconds=investigation_report["duration_seconds"],
                    iocs_found=len(iocs.get("ips", [])) + len(iocs.get("domains", [])),
                    timeline_events=len(timeline))
            
        except Exception as e:
            log.error("Investigation failed",
                     incident_id=incident_id,
                     error=str(e),
                     exc_info=True)
            
            # Send error notification
            await queue.push("notification", {
                "type": "investigation_error",
                "incident_id": incident_id,
                "severity": "P2",
                "error": str(e),
                "summary": f"Investigation failed: {str(e)}"
            })
    
    async def _collect_forensic_evidence(self, incident_id: str, resource: str) -> Dict[str, Any]:
        """Collect comprehensive forensic evidence."""
        log.info("Collecting forensic evidence", incident_id=incident_id)
        
        forensic_collector = self.collector_manager.get_collector('forensic_collector')
        if not forensic_collector:
            log.warning("Forensic collector not available")
            return {}
        
        try:
            result = await forensic_collector.collect_incident_forensics(
                incident_id=incident_id,
                resource=resource
            )
            
            log.info("Forensic evidence collected",
                    incident_id=incident_id,
                    artifacts=result.get("artifacts_collected", 0))
            
            return result
        
        except Exception as e:
            log.error("Forensic collection failed", error=str(e))
            return {}
    
    async def _analyze_logs(self, incident_id: str, resource: str) -> Dict[str, Any]:
        """Analyze logs for suspicious patterns."""
        log.info("Analyzing logs", incident_id=incident_id)
        
        log_collector = self.collector_manager.get_collector('log_collector')
        if not log_collector:
            log.warning("Log collector not available")
            return {"logs": [], "patterns": []}
        
        try:
            # Get logs for the incident timeframe
            logs = await log_collector.get_logs_for_incident(resource, time_range=7200)  # 2 hours
            
            # Search for suspicious patterns
            suspicious_patterns = []
            threat_patterns = [
                'error', 'exception', 'fail', 'attack', 'malware',
                'unauthorized', 'denied', 'blocked', 'suspicious'
            ]
            
            for pattern in threat_patterns:
                pattern_logs = await log_collector.search_logs_by_pattern(
                    pattern, time_range=7200
                )
                if pattern_logs:
                    suspicious_patterns.append({
                        'pattern': pattern,
                        'matches': len(pattern_logs),
                        'logs': pattern_logs[:5]  # First 5 matches
                    })
            
            log.info("Log analysis completed",
                    total_logs=len(logs),
                    suspicious_patterns=len(suspicious_patterns))
            
            return {
                "logs": logs,
                "suspicious_patterns": suspicious_patterns,
                "total_logs_analyzed": len(logs)
            }
        
        except Exception as e:
            log.error("Log analysis failed", error=str(e))
            return {"logs": [], "patterns": []}
    
    async def _analyze_network_activity(self, incident_id: str) -> Dict[str, Any]:
        """Analyze network activity for the incident."""
        log.info("Analyzing network activity", incident_id=incident_id)
        
        network_collector = self.collector_manager.get_collector('network_collector')
        if not network_collector:
            log.warning("Network collector not available")
            return {"connections": [], "summary": {}}
        
        try:
            # Get network connections for incident timeframe
            connections = await network_collector.get_connections_for_incident(timeframe=7200)
            
            # Get connection summary
            summary = await network_collector.get_connection_summary()
            
            log.info("Network analysis completed",
                    connections=len(connections),
                    unique_destinations=summary.get("unique_destinations", 0))
            
            return {
                "connections": connections,
                "summary": summary,
                "total_connections": len(connections)
            }
        
        except Exception as e:
            log.error("Network analysis failed", error=str(e))
            return {"connections": [], "summary": {}}
    
    async def _analyze_host_state(self, incident_id: str) -> Dict[str, Any]:
        """Analyze host state and processes."""
        log.info("Analyzing host state", incident_id=incident_id)
        
        host_collector = self.collector_manager.get_collector('host_collector')
        if not host_collector:
            log.warning("Host collector not available")
            return {"processes": [], "system_info": {}}
        
        try:
            # Get process snapshot
            process_snapshot = await host_collector.get_process_snapshot()
            
            # Get system information
            system_info = await host_collector.get_system_info()
            
            log.info("Host analysis completed",
                    processes=process_snapshot.get("total_processes", 0))
            
            return {
                "process_snapshot": process_snapshot,
                "system_info": system_info
            }
        
        except Exception as e:
            log.error("Host analysis failed", error=str(e))
            return {"processes": [], "system_info": {}}
    
    async def _reconstruct_timeline(self, request: Dict[str, Any], 
                                   forensic_data: Dict[str, Any],
                                   log_analysis: Dict[str, Any],
                                   network_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Reconstruct timeline of events."""
        log.info("Reconstructing timeline")
        
        reconstructor = TimelineReconstructor()
        
        # Add incident detection event
        reconstructor.add_incident_timeline(request)
        
        # Add forensic events
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
    
    async def _analyze_lateral_movement(self, network_analysis: Dict[str, Any],
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
    
    async def _perform_root_cause_analysis(self, request: Dict[str, Any],
                                          forensic_data: Dict[str, Any],
                                          log_analysis: Dict[str, Any],
                                          network_analysis: Dict[str, Any],
                                          timeline: List[Dict[str, Any]],
                                          iocs: Dict[str, Any],
                                          lateral_movement: Dict[str, Any]) -> Dict[str, Any]:
        """Perform LLM-powered root cause analysis."""
        log.info("Performing root cause analysis")
        
        try:
            # Build comprehensive context for LLM
            context = {
                "incident": request,
                "forensic_summary": {
                    "artifacts_collected": forensic_data.get("artifacts_collected", 0),
                    "evidence_package": forensic_data.get("evidence_package", "Not available")
                },
                "log_summary": {
                    "total_logs": log_analysis.get("total_logs_analyzed", 0),
                    "suspicious_patterns": len(log_analysis.get("suspicious_patterns", []))
                },
                "network_summary": {
                    "total_connections": network_analysis.get("total_connections", 0),
                    "unique_destinations": network_analysis.get("summary", {}).get("unique_destinations", 0)
                },
                "timeline_events": len(timeline),
                "iocs_found": {
                    "ips": len(iocs.get("ips", [])),
                    "domains": len(iocs.get("domains", [])),
                    "commands": len(iocs.get("suspicious_commands", []))
                },
                "lateral_movement_risk": lateral_movement.get("overall_risk_score", 0),
                "key_timeline_events": timeline[-10:] if timeline else [],  # Last 10 events
                "top_iocs": {
                    "ips": iocs.get("ips", [])[:5],  # Top 5 IPs
                    "domains": iocs.get("domains", [])[:5],  # Top 5 domains
                    "commands": iocs.get("suspicious_commands", [])[:3]  # Top 3 commands
                }
            }
            
            # Use LLM for root cause analysis
            root_cause_analysis = await llm_client.analyze_incident_root_cause(
                incident=request,
                context=context
            )
            
            log.info("Root cause analysis completed",
                    confidence=root_cause_analysis.get("confidence", 0))
            
            return root_cause_analysis
        
        except Exception as e:
            log.error("Root cause analysis failed", error=str(e))
            
            # Fallback analysis
            return {
                "summary": f"Automated analysis for incident {request.get('incident_id', 'unknown')}",
                "attack_vector": "Unknown - LLM analysis failed",
                "confidence": 0.5,
                "recommendations": [
                    "Review forensic evidence manually",
                    "Investigate suspicious IOCs found",
                    "Monitor for lateral movement indicators"
                ],
                "error": str(e)
            }
    
    def _generate_investigation_report(self, **kwargs) -> Dict[str, Any]:
        """Generate comprehensive investigation report."""
        report_id = str(uuid.uuid4())[:8]
        
        report = {
            "id": report_id,
            "incident_id": kwargs["incident_id"],
            "generated_at": datetime.utcnow().isoformat(),
            "duration_seconds": kwargs["duration"],
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
                "root_cause_confidence": kwargs["root_cause"].get("confidence", 0.0)
            }
        }
        
        return report
    
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
    
    def get_stats(self) -> Dict[str, Any]:
        """Get investigation agent statistics."""
        return {
            "total_investigations": self.investigation_count,
            "successful_investigations": self.success_count,
            "success_rate": (
                self.success_count / self.investigation_count 
                if self.investigation_count > 0 else 0
            ),
            "collectors_available": self.collector_manager.list_collectors() if self.collector_manager else []
        }


# Agent instance
investigation_agent = InvestigationAgent()