"""
Triage Agent - Combined Implementation
Features:
- Enriches incidents with MITRE ATT&CK mapping, asset criticality, and Action Registry capabilities
- Uses LLM to analyze: severity, confidence, false positive detection, reasoning chain
- Validates recommended actions against Action Registry
- Saves enriched incident with reasoning chain
- Hands off to trust engine for decision making
- Does NOT decide auto vs approval (delegated to trust engine)
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import structlog

from core import (
    queue, llm_client, save_enriched_incident, save_reasoning_chain,
    update_incident, EnrichedIncident, Severity,
    ActionMode, ReasoningStep, IncidentStatus
)
from core.actions import ActionRegistry

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings
# ---------------------------------------------------------------------------
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
    },
    "anomalous_cpu": {
        "tactic": "Impact",
        "technique": "T1496 - Resource Hijacking",
        "description": "Abnormal CPU usage may indicate resource hijacking"
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique": "T1046 - Network Service Scanning",
        "description": "Adversaries may scan networks to discover services"
    }
}

# ---------------------------------------------------------------------------
# Threat-to-action recommendations (used as fallback if LLM doesn't provide)
# ---------------------------------------------------------------------------
THREAT_ACTION_MAPPINGS = {
    "cryptominer": [
        {"action": "delete_pod",      "priority": 1, "reason": "Stop resource hijacking immediately"},
        {"action": "network_isolate", "priority": 2, "reason": "Prevent pool reconnection"},
        {"action": "pause_container", "priority": 3, "reason": "Preserve forensics before deletion"},
    ],
    "data_exfiltration": [
        {"action": "network_isolate", "priority": 1, "reason": "Stop data exfiltration immediately"},
        {"action": "pause_container", "priority": 2, "reason": "Freeze compromised container"},
        {"action": "delete_pod",      "priority": 3, "reason": "Remove compromised container"},
    ],
    "privilege_escalation": [
        {"action": "pause_container", "priority": 1, "reason": "Freeze before lateral movement"},
        {"action": "network_isolate", "priority": 2, "reason": "Prevent lateral movement"},
        {"action": "delete_pod",      "priority": 3, "reason": "Remove compromised container"},
    ],
    "reverse_shell": [
        {"action": "network_isolate", "priority": 1, "reason": "Cut off C2 communication"},
        {"action": "pause_container", "priority": 2, "reason": "Freeze the shell process"},
        {"action": "delete_pod",      "priority": 3, "reason": "Terminate malicious container"},
    ],
    "container_escape": [
        {"action": "network_isolate", "priority": 1, "reason": "Contain potential host breach"},
        {"action": "delete_pod",      "priority": 2, "reason": "Prevent host compromise"},
        {"action": "pause_container", "priority": 3, "reason": "Preserve evidence"},
    ],
    "anomalous_cpu": [
        {"action": "pause_container", "priority": 1, "reason": "Reduce CPU abuse"},
        {"action": "network_isolate", "priority": 2, "reason": "Prevent mining pool access"},
    ],
    "port_scan": [
        {"action": "network_isolate", "priority": 1, "reason": "Block scanner from network"},
        {"action": "pause_container", "priority": 2, "reason": "Stop scanning process"},
    ]
}


def _convert_to_reasoning_step(step_data: Any) -> ReasoningStep:
    """
    Convert various reasoning step formats to ReasoningStep model.

    Handles:
    - Already a ReasoningStep instance
    - Dict with 'type' and 'content' keys (canonical format)
    - Dict with old format keys (step_number, thought, evidence, conclusion)
    - Any other format -> converts to observation
    """
    if isinstance(step_data, ReasoningStep):
        return step_data

    if isinstance(step_data, dict):
        # Canonical format
        if "type" in step_data and "content" in step_data:
            return ReasoningStep(**step_data)

        # Old format conversion
        if "thought" in step_data or "evidence" in step_data or "conclusion" in step_data:
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

        # Generic dict -> observation
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
    """Enriches incident with MITRE, criticality, and Action Registry information."""

    def __init__(self):
        self._available_actions_cache = None
        self._capabilities_cache = None
        self._cache_timestamp = None
        self._cache_ttl = 60  # seconds

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
            "description": "No MITRE mapping available"
        })

    def _assess_criticality(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Assess asset criticality based on namespace and resource."""
        namespace = incident.get("namespace", "default")
        resource = incident.get("resource", "")

        critical_namespaces = ["production", "prod", "kube-system", "istio-system"]
        critical_resources = ["database", "db", "api", "gateway", "auth"]

        score = 5  # base
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
        """Find similar past incidents (placeholder for vector search)."""
        return []

    def _refresh_cache_if_needed(self):
        """Refresh Action Registry cache if stale."""
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

        recommended = []
        unavailable = []

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
                recommended.append(action_rec)
            else:
                unavailable.append(action_name)

        if unavailable:
            log.warning("Some mapped actions not available in registry",
                       threat_type=threat_type, unavailable=unavailable,
                       available_count=len(recommended))

        if not recommended:
            log.error("No registry actions available for threat type",
                     threat_type=threat_type,
                     mapped_actions=[m["action"] for m in action_mappings])
            return self._build_fallback_recommendations()

        recommended.sort(key=lambda x: x.get("priority", 999))
        return recommended

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
        fallback = []
        if ActionRegistry.has("capture_logs"):
            cap = ActionRegistry.get_capability("capture_logs")
            fallback.append({
                "action": "capture_logs",
                "priority": 1,
                "reason": "Fallback: Gather forensic evidence",
                "params": {"duration": 300},
                "available": True,
                "destructive": cap.destructive if cap else False,
                "reversible": cap.reversible if cap else True
            })
        if not fallback:
            fallback.append({
                "action": "manual_investigation",
                "priority": 99,
                "reason": "No automated actions available - manual investigation required",
                "params": {},
                "available": False,
                "destructive": False,
                "reversible": True
            })
        return fallback


class TriageAgent:
    """Main triage agent that enriches, analyzes, and hands off to trust engine."""

    def __init__(self):
        self.enricher = ContextEnricher()
        self.running = False
        self._log_registry_status()

    def _log_registry_status(self):
        stats = ActionRegistry.get_stats()
        available = ActionRegistry.list_available()
        log.info("Triage Agent initialized with Action Registry",
                 total_executors=stats['total_executors'],
                 available_actions=available,
                 destructive_count=stats['destructive_count'],
                 reversible_count=stats['reversible_count'])

        covered, uncovered = [], []
        for threat, mappings in THREAT_ACTION_MAPPINGS.items():
            if any(ActionRegistry.has(m["action"]) for m in mappings):
                covered.append(threat)
            else:
                uncovered.append(threat)
        log.info("Threat type coverage", covered=covered, uncovered=uncovered)

    async def start(self):
        self.running = True
        log.info("Triage Agent started")
        await self._triage_loop()

    async def stop(self):
        self.running = False
        log.info("Triage Agent stopped")

    async def _triage_loop(self):
        while self.running:
            try:
                incident_data = await queue.pop("triage", timeout=5)
                if incident_data:
                    await self._process_incident(incident_data)
            except Exception as e:
                log.error("Error in triage loop", error=str(e), exc_info=True)
                await asyncio.sleep(1)

    async def _process_incident(self, incident: Dict[str, Any]):
        incident_id = incident.get("id")
        threat_type = incident.get("type")

        # Normalize threat taxonomy (e.g., cpu_bomb -> anomalous_cpu)
        if threat_type == "cpu_bomb":
            incident["type"] = "anomalous_cpu"
            threat_type = "anomalous_cpu"

        log.info("Triaging incident", incident_id=incident_id, threat_type=threat_type)

        try:
            # 1. Enrich context
            context = await self.enricher.enrich(incident)

            # 2. LLM analysis
            analysis = await llm_client.analyze_incident(incident, context)
            log.debug("LLM analysis complete", incident_id=incident_id,
                      confidence=analysis.get("confidence"))

            # 3. False positive check
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

            # 4. Parse and validate severity (prevent downgrade of P1)
            original_severity = incident.get("severity", "P3")
            llm_severity = analysis.get("severity", original_severity)
            if original_severity == "P1" and llm_severity != "P1":
                severity = Severity.P1
            else:
                severity = Severity(llm_severity)

            confidence = min(max(analysis.get("confidence", 0.5), 0.0), 1.0)

            # 5. Get recommended actions (LLM or fallback)
            actions = analysis.get("recommended_actions", [])
            if not actions:
                actions = context.get("recommended_actions", [])

            # 6. Validate actions against Action Registry
            actions = self._validate_actions(actions)
            actions = self._deduplicate_destructive_actions(actions)

            # 7. Build reasoning chain (proper conversion)
            reasoning_chain = []
            for step in analysis.get("reasoning_chain", []):
                try:
                    reasoning_chain.append(_convert_to_reasoning_step(step))
                except Exception as e:
                    log.warning("Failed to convert reasoning step", step=step, error=str(e))
                    reasoning_chain.append(ReasoningStep(type="observation", content=str(step)))

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
                action_mode=ActionMode.APPROVAL_REQUIRED,  # will be overridden by trust engine
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

            # 9. Save to database (JSON-safe)
            safe_enriched = json.loads(json.dumps(enriched.model_dump(mode="json")))
            safe_reasoning = json.loads(json.dumps([r.model_dump(mode="json") for r in reasoning_chain]))
            await save_enriched_incident(safe_enriched)
            await save_reasoning_chain(incident_id, safe_reasoning)
            await update_incident(incident_id, {
                "status": IncidentStatus.TRIAGED.value,
                "severity": severity.value
            })

            # 10. Hand off to trust engine
            await queue.push("decision", {
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
            log.error("Triage failed", incident_id=incident_id, error=str(e), exc_info=True)
            await queue.push("notification", {
                "type": "triage_error",
                "incident_id": incident_id,
                "severity": "P2",
                "summary": f"Triage failed: {str(e)}"
            })

    def _validate_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter actions to those present in Action Registry, enrich with capabilities."""
        validated = []
        invalid = []
        for action in actions:
            name = action.get("action")
            if ActionRegistry.has(name):
                cap = ActionRegistry.get_capability(name)
                if cap:
                    action.update({
                        "description": cap.description,
                        "destructive": cap.destructive,
                        "reversible": cap.reversible,
                        "requires_snapshot": cap.requires_snapshot,
                        "min_trust_level": cap.min_trust_level
                    })
                validated.append(action)
            else:
                invalid.append(name)
                log.warning("Action recommended by LLM but not in registry", action=name)
        if invalid:
            log.info("Filtered out invalid actions", invalid=invalid, kept=len(validated))
        validated.sort(key=lambda x: (x.get("priority", 999), x.get("destructive", False)))
        return validated

    def _deduplicate_destructive_actions(self, actions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """If multiple destructive actions exist, keep only the highest priority one."""
        destructive = [a for a in actions if a.get("destructive")]
        if not destructive:
            return actions

        destructive.sort(key=lambda x: x.get("priority", 999))
        top_destructive = destructive[0]

        filtered = []
        for action in actions:
            if action.get("destructive"):
                if action["action"] == top_destructive["action"]:
                    filtered.append(action)
            else:
                filtered.append(action)
        return filtered


# Agent instance
triage_agent = TriageAgent()