"""
Triage Agent - Week 2, Days 1-4
Enriches incidents with context, uses LLM for analysis, generates reasoning chains.

FIXED: Properly converts LLM reasoning to ReasoningStep format
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

# Correct import path matching Containment Agent
from core.actions import ActionRegistry

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

# Lightweight threat-to-action-name mappings
THREAT_ACTION_MAPPINGS = {
    "cryptominer": [
        {"action": "delete_container", "priority": 1, "reason": "Stop resource hijacking immediately"},
        {"action": "capture_logs", "priority": 2, "reason": "Preserve forensic evidence"},
        {"action": "block_registry", "priority": 3, "reason": "Prevent redeployment"}
    ],
    "data_exfiltration": [
        {"action": "isolate_network", "priority": 1, "reason": "Stop data exfiltration immediately"},
        {"action": "capture_logs", "priority": 2, "reason": "Capture network activity logs"},
        {"action": "delete_container", "priority": 3, "reason": "Remove compromised container"}
    ],
    "privilege_escalation": [
        {"action": "delete_container", "priority": 1, "reason": "Remove compromised container immediately"},
        {"action": "isolate_network", "priority": 2, "reason": "Prevent lateral movement"},
        {"action": "capture_logs", "priority": 3, "reason": "Preserve audit trail"}
    ],
    "reverse_shell": [
        {"action": "isolate_network", "priority": 1, "reason": "Cut off C2 communication"},
        {"action": "delete_container", "priority": 2, "reason": "Terminate malicious process"},
        {"action": "capture_logs", "priority": 3, "reason": "Collect connection logs"}
    ],
    "container_escape": [
        {"action": "delete_container", "priority": 1, "reason": "Prevent host compromise"},
        {"action": "isolate_network", "priority": 2, "reason": "Contain potential breach"},
        {"action": "capture_logs", "priority": 3, "reason": "Forensic analysis"}
    ],
    "suspicious_process": [
        {"action": "capture_logs", "priority": 1, "reason": "Gather evidence before action"},
        {"action": "isolate_network", "priority": 2, "reason": "Limit blast radius while investigating"}
    ]
}


def _convert_to_reasoning_step(step_data: Any) -> ReasoningStep:
    """
    Convert various reasoning step formats to ReasoningStep model.
    
    Handles:
    - Already a ReasoningStep instance
    - Dict with 'type' and 'content' keys (correct format)
    - Dict with old format keys (step_number, thought, evidence, conclusion)
    - Any other format - converts to observation
    """
    # Already correct type
    if isinstance(step_data, ReasoningStep):
        return step_data
    
    # Dict with correct format
    if isinstance(step_data, dict):
        if "type" in step_data and "content" in step_data:
            return ReasoningStep(**step_data)
        
        # Old format conversion
        if "thought" in step_data or "evidence" in step_data or "conclusion" in step_data:
            # Combine all fields into content
            parts = []
            if "thought" in step_data:
                parts.append(f"Thought: {step_data['thought']}")
            if "evidence" in step_data:
                parts.append(f"Evidence: {step_data['evidence']}")
            if "conclusion" in step_data:
                parts.append(f"Conclusion: {step_data['conclusion']}")
            
            content = " | ".join(parts) if parts else str(step_data)
            
            # Determine type based on content
            step_type = "analysis"
            if "conclusion" in step_data:
                step_type = "conclusion"
            elif "hypothesis" in str(step_data).lower():
                step_type = "hypothesis"
            
            return ReasoningStep(
                type=step_type,
                content=content,
                confidence=step_data.get("confidence")
            )
        
        # Generic dict - convert to observation
        return ReasoningStep(
            type="observation",
            content=str(step_data)
        )
    
    # Fallback for any other type
    return ReasoningStep(
        type="observation",
        content=str(step_data)
    )


class ContextEnricher:
    """Enriches incident with additional context from Action Registry."""
    
    def __init__(self):
        # Cache available actions to avoid repeated registry lookups
        self._available_actions_cache = None
        self._capabilities_cache = None
        self._cache_timestamp = None
        self._cache_ttl = 60  # Refresh cache every 60 seconds
    
    async def enrich(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Gather all context for an incident."""
        context = {
            "timestamp": datetime.utcnow().isoformat(),
            "mitre_mapping": self._get_mitre_mapping(incident.get("type")),
            "asset_criticality": self._assess_criticality(incident),
            "similar_incidents": await self._find_similar(incident),
            "recommended_actions": self._get_recommended_actions(incident.get("type")),
            "available_actions": self._get_available_actions_summary(),
            "action_capabilities": self._get_action_capabilities()
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
        return []
    
    def _refresh_cache_if_needed(self):
        """Refresh action registry cache if stale."""
        now = datetime.utcnow().timestamp()
        
        if (self._cache_timestamp is None or 
            (now - self._cache_timestamp) > self._cache_ttl):
            
            self._available_actions_cache = ActionRegistry.list_available()
            self._capabilities_cache = ActionRegistry.get_capabilities()
            self._cache_timestamp = now
            
            log.debug("Action registry cache refreshed",
                     actions_count=len(self._available_actions_cache))
    
    def _get_available_actions_summary(self) -> Dict[str, Any]:
        """Get summary of available actions from registry."""
        self._refresh_cache_if_needed()
        
        stats = ActionRegistry.get_stats()
        
        return {
            "total_actions": stats['total_executors'],
            "actions": self._available_actions_cache,
            "destructive_count": stats['destructive_count'],
            "reversible_count": stats['reversible_count']
        }
    
    def _get_action_capabilities(self) -> Dict[str, Dict[str, Any]]:
        """Get capabilities of all registered actions."""
        self._refresh_cache_if_needed()
        
        capabilities = {}
        for action_name, capability in self._capabilities_cache.items():
            capabilities[action_name] = {
                "action_name": capability.action_name,
                "description": capability.description,
                "destructive": capability.destructive,
                "requires_snapshot": capability.requires_snapshot,
                "reversible": capability.reversible,
                "required_params": capability.required_params,
                "optional_params": capability.optional_params,
                "supported_platforms": capability.supported_platforms,
                "min_trust_level": capability.min_trust_level,
                "estimated_duration_seconds": capability.estimated_duration_seconds,
                "timeout_seconds": capability.timeout_seconds
            }
        
        return capabilities
    
    def _get_recommended_actions(self, threat_type: str) -> List[Dict[str, Any]]:
        """Get recommended actions by querying Action Registry."""
        self._refresh_cache_if_needed()
        
        action_mappings = THREAT_ACTION_MAPPINGS.get(threat_type, [])
        
        if not action_mappings:
            log.warning("Unknown threat type, returning all available actions",
                       threat_type=threat_type)
            return self._build_generic_recommendations()
        
        recommended_actions = []
        unavailable_actions = []
        
        for mapping in action_mappings:
            action_name = mapping["action"]
            
            if ActionRegistry.has(action_name):
                capability = ActionRegistry.get_capability(action_name)
                
                action_rec = {
                    "action": action_name,
                    "priority": mapping.get("priority", 5),
                    "reason": mapping.get("reason", "Recommended action"),
                    "params": mapping.get("params", {}),
                    "available": True
                }
                
                if capability:
                    action_rec.update({
                        "description": capability.description,
                        "destructive": capability.destructive,
                        "reversible": capability.reversible,
                        "requires_snapshot": capability.requires_snapshot,
                        "min_trust_level": capability.min_trust_level,
                        "estimated_duration_seconds": capability.estimated_duration_seconds
                    })
                
                recommended_actions.append(action_rec)
            else:
                unavailable_actions.append(action_name)
        
        if unavailable_actions:
            log.warning("Some mapped actions not available in registry",
                       threat_type=threat_type,
                       unavailable=unavailable_actions,
                       available_count=len(recommended_actions))
        
        if not recommended_actions:
            log.error("No registry actions available for threat type", 
                     threat_type=threat_type,
                     mapped_actions=[m["action"] for m in action_mappings],
                     registry_actions=self._available_actions_cache)
            return self._build_fallback_recommendations()
        
        recommended_actions.sort(key=lambda x: x.get("priority", 999))
        return recommended_actions
    
    def _build_generic_recommendations(self) -> List[Dict[str, Any]]:
        """Build generic recommendations from all available actions."""
        self._refresh_cache_if_needed()
        
        recommendations = []
        
        for action_name in self._available_actions_cache:
            capability = ActionRegistry.get_capability(action_name)
            
            if capability:
                priority = 1 if not capability.destructive else 2
                recommendations.append({
                    "action": action_name,
                    "priority": priority,
                    "reason": capability.description or "Available action",
                    "params": {},
                    "available": True,
                    "destructive": capability.destructive,
                    "reversible": capability.reversible,
                    "min_trust_level": capability.min_trust_level
                })
        
        recommendations.sort(key=lambda x: x["priority"])
        return recommendations
    
    def _build_fallback_recommendations(self) -> List[Dict[str, Any]]:
        """Build safe fallback recommendations when no actions match."""
        fallback_actions = []
        
        if ActionRegistry.has("capture_logs"):
            capability = ActionRegistry.get_capability("capture_logs")
            fallback_actions.append({
                "action": "capture_logs",
                "priority": 1,
                "reason": "Fallback: Gather forensic evidence",
                "params": {"duration": 300},
                "available": True,
                "destructive": capability.destructive if capability else False,
                "reversible": capability.reversible if capability else True
            })
        
        if not fallback_actions:
            fallback_actions.append({
                "action": "manual_investigation",
                "priority": 99,
                "reason": "No automated actions available - manual investigation required",
                "params": {},
                "available": False,
                "destructive": False,
                "reversible": True
            })
        
        return fallback_actions


class TriageAgent:
    """Main triage agent that enriches and analyzes incidents."""
    
    def __init__(self):
        self.enricher = ContextEnricher()
        self.running = False
        self._log_registry_status()
    
    def _log_registry_status(self):
        """Log Action Registry status on startup."""
        stats = ActionRegistry.get_stats()
        available_actions = ActionRegistry.list_available()
        
        log.info("Triage Agent initialized with Action Registry",
                 total_executors=stats['total_executors'],
                 available_actions=available_actions,
                 destructive_count=stats['destructive_count'],
                 reversible_count=stats['reversible_count'])
        
        covered_threats = []
        uncovered_threats = []
        
        for threat_type, mappings in THREAT_ACTION_MAPPINGS.items():
            has_actions = any(
                ActionRegistry.has(m["action"]) 
                for m in mappings
            )
            if has_actions:
                covered_threats.append(threat_type)
            else:
                uncovered_threats.append(threat_type)
        
        log.info("Threat type coverage",
                 covered=covered_threats,
                 uncovered=uncovered_threats)
    
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
                log.error("Error in triage loop", error=str(e), exc_info=True)
                await asyncio.sleep(1)
    
    async def _process_incident(self, incident: Dict[str, Any]):
        """Process a single incident through triage pipeline."""
        incident_id = incident.get("id")
        threat_type = incident.get("type")
        
        log.info("Triaging incident", 
                 incident_id=incident_id, 
                 threat_type=threat_type)
        
        try:
            # 1. Enrich context
            context = await self.enricher.enrich(incident)
            
            available_count = len(context.get("available_actions", {}).get("actions", []))
            recommended_count = len(context.get("recommended_actions", []))
            
            log.debug("Context enriched", 
                     incident_id=incident_id,
                     available_actions=available_count,
                     recommended_actions=recommended_count)
            
            # 2. LLM analysis
            analysis = await llm_client.analyze_incident(incident, context)
            log.debug("LLM analysis complete", 
                     incident_id=incident_id,
                     confidence=analysis.get("confidence"))
            
            # 3. Check for false positive
            if analysis.get("is_false_positive"):
                await update_incident(incident_id, {"status": IncidentStatus.FALSE_POSITIVE.value})
                await queue.push("notification", {
                    "type": "false_positive",
                    "incident_id": incident_id,
                    "severity": "P4",
                    "summary": "Incident marked as false positive by triage",
                    "reasoning": analysis.get("summary", "LLM determined this is not a real threat")
                })
                log.info("Incident marked as false positive", incident_id=incident_id)
                return
            
            # 4. Parse and validate analysis
            severity = Severity(analysis.get("severity", "P3"))
            confidence = min(max(analysis.get("confidence", 0.5), 0.0), 1.0)
            
            # 5. Get recommended actions
            actions = analysis.get("recommended_actions", [])
            if not actions:
                actions = context.get("recommended_actions", [])
            
            # 6. Validate actions
            actions = self._validate_actions(actions)
            
            # 7. Build reasoning chain - PROPER CONVERSION
            reasoning_chain = []
            
            # Convert LLM reasoning chain using helper function
            for step in analysis.get("reasoning_chain", []):
                try:
                    reasoning_step = _convert_to_reasoning_step(step)
                    reasoning_chain.append(reasoning_step)
                except Exception as e:
                    log.warning("Failed to convert reasoning step", 
                               step=step, 
                               error=str(e))
                    # Fallback: create a basic observation
                    reasoning_chain.append(ReasoningStep(
                        type="observation",
                        content=str(step)
                    ))
            
            # Add registry validation step
            registry_stats = ActionRegistry.get_stats()
            reasoning_chain.append(ReasoningStep(
                type="validation",
                content=f"Validated {len(actions)} recommended actions against Action Registry. "
                       f"All actions have registered executors: {[a['action'] for a in actions]}. "
                       f"Registry has {registry_stats['total_executors']} total executors available.",
                confidence=1.0
            ))
            
            # 8. Create enriched incident
            enriched = EnrichedIncident(
                incident_id=incident_id,
                severity=severity,
                confidence=confidence,
                recommended_actions=actions,
                action_mode=ActionMode.APPROVAL_REQUIRED,
                reasoning_chain=reasoning_chain,
                context={
                    **context,
                    "llm_analysis": analysis.get("summary", ""),
                    "action_validation": {
                        "validated_at": datetime.utcnow().isoformat(),
                        "actions_available": len(actions),
                        "registry_stats": registry_stats
                    }
                }
            )
            
            # 9. Save to database
            await save_enriched_incident(enriched.model_dump(mode='json'))
            await save_reasoning_chain(incident_id, [r.model_dump() for r in reasoning_chain])
            await update_incident(incident_id, {
                "status": IncidentStatus.TRIAGED.value,
                "severity": severity.value
            })
            
            # 10. Push to trust engine
            await queue.push("trust_decision", {
                "incident_id": incident_id,
                "enriched_id": enriched.id,
                "severity": severity.value,
                "confidence": confidence,
                "recommended_actions": actions,
                "context": enriched.context
            })
            
            # 11. Send notification
            await queue.push("notification", {
                "type": "triage_complete",
                "incident_id": incident_id,
                "severity": severity.value,
                "confidence": confidence,
                "action_mode": "PENDING_TRUST_DECISION",
                "actions": actions,
                "reasoning_summary": analysis.get("summary", "Analysis complete"),
                "actions_available": len(actions),
                "registry_validated": True
            })
            
            log.info("Triage complete",
                     incident_id=incident_id,
                     severity=severity.value,
                     confidence=confidence,
                     actions_count=len(actions),
                     registry_validated=True)
            
        except Exception as e:
            log.error("Triage failed", 
                     incident_id=incident_id, 
                     error=str(e),
                     exc_info=True)
            await queue.push("notification", {
                "type": "triage_error",
                "incident_id": incident_id,
                "severity": "P2",
                "summary": f"Triage failed: {str(e)}"
            })
    
    def _validate_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate that all recommended actions exist in registry."""
        validated_actions = []
        invalid_actions = []
        
        for action in actions:
            action_name = action.get("action")
            
            if ActionRegistry.has(action_name):
                if "destructive" not in action:
                    capability = ActionRegistry.get_capability(action_name)
                    if capability:
                        action.update({
                            "description": capability.description,
                            "destructive": capability.destructive,
                            "reversible": capability.reversible,
                            "requires_snapshot": capability.requires_snapshot,
                            "min_trust_level": capability.min_trust_level
                        })
                
                validated_actions.append(action)
            else:
                invalid_actions.append(action_name)
                log.warning("Action recommended by LLM but not in registry",
                           action=action_name)
        
        if invalid_actions:
            log.info("Filtered out invalid actions",
                    invalid=invalid_actions,
                    kept=len(validated_actions))
        
        return validated_actions


# Agent instance
triage_agent = TriageAgent()