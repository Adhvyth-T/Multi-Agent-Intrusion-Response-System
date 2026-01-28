"""
Triage Agent - Week 2, Days 1-4
Enriches incidents with context, uses LLM for analysis, generates reasoning chains.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import structlog

from core import (
    queue, llm_client, save_enriched_incident, save_reasoning_chain,
    update_incident, get_incident, EnrichedIncident, Severity, 
    ActionMode, ReasoningStep, IncidentStatus
)

log = structlog.get_logger()

# MITRE ATT&CK mapping for common threats
MITRE_MAPPING = {
    "cryptominer": {
        "tactic": "Impact",
        "technique": "T1496 - Resource Hijacking",
        "description": "Adversaries may leverage compute resources for cryptocurrency mining"
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique": "T1041 - Exfiltration Over C2 Channel",
        "description": "Adversaries may steal data by exfiltrating it over an existing C2 channel"
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique": "T1068 - Exploitation for Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities to elevate privileges"
    },
    "reverse_shell": {
        "tactic": "Command and Control",
        "technique": "T1059 - Command and Scripting Interpreter",
        "description": "Adversaries may abuse command interpreters to execute commands"
    },
    "container_escape": {
        "tactic": "Privilege Escalation",
        "technique": "T1611 - Escape to Host",
        "description": "Adversaries may break out of a container to gain access to the host"
    }
}

# Containment action recommendations
CONTAINMENT_ACTIONS = {
    "cryptominer": [
        {"action": "delete_pod", "params": {"grace_period": 0}, "priority": 1},
        {"action": "block_registry", "params": {"reason": "malware"}, "priority": 2},
        {"action": "revoke_service_account", "params": {}, "priority": 3}
    ],
    "data_exfiltration": [
        {"action": "network_isolate", "params": {"policy": "deny-egress"}, "priority": 1},
        {"action": "block_ip", "params": {"direction": "egress"}, "priority": 2},
        {"action": "capture_logs", "params": {"duration": 300}, "priority": 3}
    ],
    "privilege_escalation": [
        {"action": "delete_pod", "params": {"force": True}, "priority": 1},
        {"action": "update_admission_policy", "params": {"rule": "deny-hostpath"}, "priority": 2},
        {"action": "audit_rbac", "params": {}, "priority": 3}
    ],
    "reverse_shell": [
        {"action": "network_isolate", "params": {"policy": "deny-all"}, "priority": 1},
        {"action": "delete_pod", "params": {"grace_period": 0}, "priority": 2},
        {"action": "capture_traffic", "params": {"duration": 60}, "priority": 3}
    ],
    "container_escape": [
        {"action": "cordon_node", "params": {}, "priority": 1},
        {"action": "delete_pod", "params": {"force": True}, "priority": 2},
        {"action": "scan_node", "params": {}, "priority": 3}
    ]
}

class ContextEnricher:
    """Enriches incident with additional context."""
    
    async def enrich(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Gather all context for an incident."""
        context = {
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_mapping": self._get_mitre_mapping(incident.get("type")),
            "asset_criticality": self._assess_criticality(incident),
            "similar_incidents": await self._find_similar(incident),
            "recommended_actions": self._get_recommended_actions(incident.get("type"))
        }
        return context
    
    def _get_mitre_mapping(self, threat_type: str) -> Dict[str, Any]:
        """Map threat to MITRE ATT&CK framework."""
        return MITRE_MAPPING.get(threat_type, {
            "tactic": "Unknown",
            "technique": "Unknown",
            "description": "No mapping available"
        })
    
    def _assess_criticality(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Assess asset criticality based on namespace and resource."""
        namespace = incident.get("namespace", "default")
        resource = incident.get("resource", "")
        
        # Critical namespaces
        critical_namespaces = ["production", "prod", "kube-system", "istio-system"]
        critical_resources = ["database", "db", "api", "gateway", "auth"]
        
        score = 5  # Base score
        reasons = []
        
        if namespace in critical_namespaces:
            score += 3
            reasons.append(f"Critical namespace: {namespace}")
        
        for crit in critical_resources:
            if crit in resource.lower():
                score += 2
                reasons.append(f"Critical resource type: {crit}")
                break
        
        return {
            "score": min(score, 10),
            "level": "critical" if score >= 8 else "high" if score >= 6 else "medium",
            "reasons": reasons
        }
    
    async def _find_similar(self, incident: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Find similar past incidents (simplified - would use vector search in production)."""
        # In a real implementation, this would query a vector database
        return []
    
    def _get_recommended_actions(self, threat_type: str) -> List[Dict[str, Any]]:
        """Get recommended containment actions for threat type."""
        return CONTAINMENT_ACTIONS.get(threat_type, [
            {"action": "investigate", "params": {}, "priority": 1}
        ])

class TriageAgent:
    """Main triage agent that enriches and analyzes incidents."""
    
    def __init__(self):
        self.enricher = ContextEnricher()
        self.running = False
    
    async def start(self):
        """Start the triage agent."""
        self.running = True
        log.info("Triage Agent started")
        
        await self._triage_loop()
    
    async def stop(self):
        """Stop the triage agent."""
        self.running = False
        log.info("Triage Agent stopped")
    
    async def _triage_loop(self):
        """Process incidents from triage queue."""
        while self.running:
            try:
                incident_data = await queue.pop("triage", timeout=5)
                
                if incident_data:
                    await self._process_incident(incident_data)
            except Exception as e:
                log.error("Error in triage", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_incident(self, incident: Dict[str, Any]):
        """Process a single incident through triage pipeline."""
        incident_id = incident.get("id")
        log.info("Triaging incident", incident_id=incident_id)
        
        try:
            # 1. Enrich context
            context = await self.enricher.enrich(incident)
            log.debug("Context enriched", incident_id=incident_id)
            
            # 2. LLM analysis
            analysis = await llm_client.analyze_incident(incident, context)
            log.debug("LLM analysis complete", incident_id=incident_id)
            
            # 3. Check for false positive
            if analysis.get("is_false_positive"):
                await update_incident(incident_id, {"status": IncidentStatus.FALSE_POSITIVE.value})
                await queue.push("notification", {
                    "type": "false_positive",
                    "incident_id": incident_id,
                    "severity": "P4",
                    "summary": "Incident marked as false positive by triage"
                })
                return
            
            # 4. Parse and validate analysis
            severity = Severity(analysis.get("severity", "P3"))
            confidence = min(max(analysis.get("confidence", 0.5), 0.0), 1.0)
            
            # Merge recommended actions
            actions = analysis.get("recommended_actions", [])
            if not actions:
                actions = context.get("recommended_actions", [])
            
            # 5. Build reasoning chain
            reasoning_chain = [
                ReasoningStep(**step) if isinstance(step, dict) else step
                for step in analysis.get("reasoning_chain", [])
            ]
            
            # 6. Request trust decision (will be handled by trust engine)
            # For now, we'll push to containment queue and let trust engine intercept
            enriched = EnrichedIncident(
                incident_id=incident_id,
                severity=severity,
                confidence=confidence,
                recommended_actions=actions,
                action_mode=ActionMode.APPROVAL_REQUIRED,  # Default, trust engine will override
                reasoning_chain=reasoning_chain,
                context={
                    **context,
                    "llm_analysis": analysis.get("summary", "")
                }
            )
            
            # 7. Save to database
            await save_enriched_incident(enriched.model_dump(mode='json'))
            await save_reasoning_chain(incident_id, [r.model_dump() for r in reasoning_chain])
            await update_incident(incident_id, {
                "status": IncidentStatus.TRIAGED.value,
                "severity": severity.value
            })
            
            # 8. Push to trust engine for decision
            await queue.push("trust_decision", {
                "incident_id": incident_id,
                "enriched_id": enriched.id,
                "severity": severity.value,
                "confidence": confidence,
                "recommended_actions": actions,
                "context": enriched.context
            })
            
            # 9. Send notification
            await queue.push("notification", {
                "type": "triage_complete",
                "incident_id": incident_id,
                "severity": severity.value,
                "confidence": confidence,
                "action_mode": "PENDING_TRUST_DECISION",
                "actions": actions,
                "reasoning_summary": analysis.get("summary", "Analysis complete")
            })
            
            log.info("Triage complete",
                     incident_id=incident_id,
                     severity=severity.value,
                     confidence=confidence,
                     actions_count=len(actions))
            
        except Exception as e:
            log.error("Triage failed", incident_id=incident_id, error=str(e))
            await queue.push("notification", {
                "type": "triage_error",
                "incident_id": incident_id,
                "severity": "P2",
                "summary": f"Triage failed: {str(e)}"
            })

# Agent instance
triage_agent = TriageAgent()
