"""
Context Agent - Central Incident Context Assembler

Assembles a rich, unified context object for any incident by querying all
relevant data sources: SQLite tables, forensic collector snapshots.

Used by:
- Decision Agent (after triage, after validation failure with retry history)
- Investigation Agent (replaces direct forensic collector access)
- Validation Agent (before calling Decision Agent on retry)

Design: Agents call assemble_context() or get_context() directly.
        No queue - this is a synchronous service layer.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import structlog

import aiosqlite
from config import config
from core import get_incident, queue

DB_PATH = config.sqlite_path

log = structlog.get_logger()

# MITRE ATT&CK mapping (moved here from triage agent - context is the right place)
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


class ContextAgent:
    """
    Assembles and maintains rich incident context throughout the pipeline.

    Each incident gets a context object that grows richer as it moves through:
    Detection → Triage → Decision → Containment → Validation → Investigation

    Context is cached in memory and updated as new data arrives.
    """

    def __init__(self):
        # In-memory cache: incident_id -> context dict
        self._context_cache: Dict[str, Dict[str, Any]] = {}
        self._forensic_collector = None  # Set via set_forensic_collector()
        log.info("Context Agent initialized")

    def set_forensic_collector(self, collector):
        """Register the global forensic collector instance."""
        self._forensic_collector = collector
        log.info("Forensic collector registered with Context Agent")

    # ================================================================
    # PRIMARY INTERFACE
    # ================================================================

    async def assemble_context(self, incident_id: str) -> Dict[str, Any]:
        """
        Build full context for an incident from all available sources.

        Queries:
        - incidents table (base incident data)
        - enriched_incidents table (triage analysis, confidence, recommended actions)
        - reasoning_chains table (LLM reasoning steps)
        - actions table (what containment was attempted)
        - action_attempts table (per-phase IVAM results, retry history)
        - validation_attempts table (detailed validation records)
        - forensic collector (live snapshot if available)

        Returns a unified context dict. Also updates the cache.
        """
        log.info("Assembling incident context", incident_id=incident_id)

        context = {
            "incident_id": incident_id,
            "assembled_at": datetime.utcnow().isoformat(),
        }

        # Query all sources concurrently
        (
            incident,
            enriched,
            reasoning_chain,
            actions,
            action_attempts,
            validation_attempts,
            forensic_snapshot,
        ) = await asyncio.gather(
            self._get_incident(incident_id),
            self._get_enriched_incident(incident_id),
            self._get_reasoning_chain(incident_id),
            self._get_actions(incident_id),
            self._get_action_attempts(incident_id),
            self._get_validation_attempts(incident_id),
            self._get_forensic_snapshot(incident_id),
            return_exceptions=True,
        )

        # Safely assign results (gather with return_exceptions returns Exception objects on failure)
        context["incident"] = incident if not isinstance(incident, Exception) else {}
        context["enriched"] = enriched if not isinstance(enriched, Exception) else {}
        context["reasoning_chain"] = reasoning_chain if not isinstance(reasoning_chain, Exception) else []
        context["actions"] = actions if not isinstance(actions, Exception) else []
        context["action_attempts"] = action_attempts if not isinstance(action_attempts, Exception) else []
        context["validation_attempts"] = validation_attempts if not isinstance(validation_attempts, Exception) else []
        context["forensic_snapshot"] = forensic_snapshot if not isinstance(forensic_snapshot, Exception) else {}

        # Derived fields
        context["mitre_mapping"] = MITRE_MAPPING.get(
            context["incident"].get("type", ""), {}
        )
        context["asset_criticality"] = self._assess_criticality(context["incident"])
        context["retry_history"] = self._build_retry_history(context["action_attempts"])
        context["containment_summary"] = self._build_containment_summary(
            context["actions"], context["action_attempts"]
        )
        context["has_live_forensics"] = bool(
            context["forensic_snapshot"] and
            context["forensic_snapshot"].get("has_live_data")
        )

        # Update cache
        self._context_cache[incident_id] = context

        log.info(
            "Context assembled",
            incident_id=incident_id,
            actions_count=len(context["actions"]),
            attempts_count=len(context["action_attempts"]),
            has_live_forensics=context["has_live_forensics"],
            retry_count=len(context["retry_history"]),
        )

        return context

    async def get_context(self, incident_id: str) -> Dict[str, Any]:
        """
        Return cached context if available, otherwise assemble fresh.
        Use this when you want fast access and don't need guaranteed freshness.
        """
        if incident_id in self._context_cache:
            return self._context_cache[incident_id]
        return await self.assemble_context(incident_id)

    async def refresh_context(self, incident_id: str) -> Dict[str, Any]:
        """
        Force a fresh DB assembly, but PRESERVE phase_updates from the old cache.

        phase_updates are in-memory annotations written by each agent as the incident
        moves through the pipeline (triage summary, containment outcomes, validation
        failures etc). They are never persisted to DB, so wiping the cache entry
        loses them permanently.

        Without this preservation, Decision Agent would never see:
        - phase_updates.validation  (why Phase 2/3 failed, e.g. container inspect failed)
        - phase_updates.containment (actions_taken with exact error messages)
        - phase_updates.triage      (llm_summary used by _select_actions_initial)
        - phase_updates.decision    (action_mode, actions_queued)
        """
        old_phase_updates = {}
        if incident_id in self._context_cache:
            old_phase_updates = self._context_cache[incident_id].get("phase_updates", {})
            del self._context_cache[incident_id]

        context = await self.assemble_context(incident_id)

        # Merge back — old in-memory list history takes precedence
        # Each phase value is a list of timestamped entries; preserve all of them
        if old_phase_updates:
            existing = context.get("phase_updates", {})
            merged = {**existing}
            for phase_key, entries in old_phase_updates.items():
                # old_phase_updates is the authoritative in-memory history list
                merged[phase_key] = entries
            context["phase_updates"] = merged
            self._context_cache[incident_id]["phase_updates"] = merged

        return context

    def update_context(self, incident_id: str, phase: str, data: Dict[str, Any]):
        """
        Append a phase update to the incident context history.

        Each call appends a new entry to phase_updates[phase] (a list), so the
        Decision Agent receives a full chronological history like:

            phase_updates:
              triage:     [{severity, confidence, llm_summary, updated_at}]
              decision:   [{action_mode, actions_queued, updated_at},   # initial
                           {action_mode, actions_queued, updated_at}]   # retry 1
              containment:[{actions_taken, last_action_message, ...},   # initial
                           {actions_taken, last_action_message, ...}]   # retry 1
              validation: [{last_failure_message, last_failure_phase},  # initial failure
                           {last_failure_message, last_failure_phase}]  # retry 1 failure

        Agents that read phase_updates should use [-1] for the latest entry
        and the full list for historical context.

        Phases: 'triage', 'decision', 'containment', 'validation', 'investigation'
        """
        if incident_id not in self._context_cache:
            # Populate cache from DB so the update isn't lost.
            # This can happen if the process restarted between pipeline stages.
            log.warning(
                "update_context: no cached context, assembling from DB first",
                incident_id=incident_id,
                phase=phase,
            )
            try:
                import asyncio
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    # Schedule cache population but proceed — the append below will work
                    # because assemble_context sets self._context_cache[incident_id]
                    # We can't await here (sync method), so we ensure the key exists
                    self._context_cache[incident_id] = {"incident_id": incident_id, "phase_updates": {}}
                else:
                    loop.run_until_complete(self.assemble_context(incident_id))
            except Exception as e:
                log.error("Failed to pre-populate cache for update_context",
                          incident_id=incident_id, error=str(e))
                self._context_cache[incident_id] = {"incident_id": incident_id, "phase_updates": {}}

        if "phase_updates" not in self._context_cache[incident_id]:
            self._context_cache[incident_id]["phase_updates"] = {}

        phase_updates = self._context_cache[incident_id]["phase_updates"]

        if phase not in phase_updates:
            phase_updates[phase] = []

        phase_updates[phase].append({
            **data,
            "updated_at": datetime.utcnow().isoformat(),
        })

        log.debug("Context updated",
                  incident_id=incident_id,
                  phase=phase,
                  history_length=len(phase_updates[phase]))

    def evict(self, incident_id: str):
        """Remove incident from cache (e.g. after investigation completes)."""
        self._context_cache.pop(incident_id, None)

    # ================================================================
    # DATA FETCHERS
    # ================================================================

    async def _get_incident(self, incident_id: str) -> Dict[str, Any]:
        """Fetch base incident record."""
        try:
            incident = await get_incident(incident_id)
            if incident and incident.get("raw_event"):
                # Parse raw_event if stored as string
                if isinstance(incident["raw_event"], str):
                    try:
                        incident["raw_event"] = json.loads(incident["raw_event"])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return incident or {}
        except Exception as e:
            log.error("Failed to fetch incident", incident_id=incident_id, error=str(e))
            return {}

    async def _get_enriched_incident(self, incident_id: str) -> Dict[str, Any]:
        """Fetch triage enrichment: confidence, severity, recommended actions."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM enriched_incidents WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                    (incident_id,),
                ) as cursor:
                    row = await cursor.fetchone()
                    if not row:
                        return {}

                    result = dict(row)
                    for field in ("recommended_actions", "context"):
                        if result.get(field) and isinstance(result[field], str):
                            try:
                                result[field] = json.loads(result[field])
                            except (json.JSONDecodeError, TypeError):
                                pass
                    return result
        except Exception as e:
            log.error("Failed to fetch enriched incident", incident_id=incident_id, error=str(e))
            return {}

    async def _get_reasoning_chain(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch LLM reasoning steps from triage."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM reasoning_chains WHERE incident_id = ? ORDER BY step_number ASC",
                    (incident_id,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    return [dict(row) for row in rows] if rows else []
        except Exception as e:
            log.error("Failed to fetch reasoning chain", incident_id=incident_id, error=str(e))
            return []

    async def _get_actions(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch all containment actions attempted for this incident."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM actions WHERE incident_id = ? ORDER BY created_at ASC",
                    (incident_id,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    results = []
                    for row in rows:
                        action = dict(row)
                        for field in ("params", "result", "details"):
                            if action.get(field) and isinstance(action[field], str):
                                try:
                                    action[field] = json.loads(action[field])
                                except (json.JSONDecodeError, TypeError):
                                    pass
                        results.append(action)
                    return results
        except Exception as e:
            log.error("Failed to fetch actions", incident_id=incident_id, error=str(e))
            return []

    async def _get_action_attempts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch action attempts with full IVAM phase results."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM action_attempts WHERE incident_id = ? ORDER BY created_at ASC",
                    (incident_id,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    results = []
                    for row in rows:
                        attempt = dict(row)
                        if attempt.get("details") and isinstance(attempt["details"], str):
                            try:
                                attempt["details"] = json.loads(attempt["details"])
                            except (json.JSONDecodeError, TypeError):
                                pass
                        results.append(attempt)
                    return results
        except Exception as e:
            log.error("Failed to fetch action attempts", incident_id=incident_id, error=str(e))
            return []

    async def _get_validation_attempts(self, incident_id: str) -> List[Dict[str, Any]]:
        """Fetch IVAM validation records."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                db.row_factory = aiosqlite.Row
                async with db.execute(
                    "SELECT * FROM validation_attempts WHERE incident_id = ? ORDER BY validated_at ASC",
                    (incident_id,),
                ) as cursor:
                    rows = await cursor.fetchall()
                    results = []
                    for row in rows:
                        attempt = dict(row)
                        if attempt.get("details") and isinstance(attempt["details"], str):
                            try:
                                attempt["details"] = json.loads(attempt["details"])
                            except (json.JSONDecodeError, TypeError):
                                pass
                        results.append(attempt)
                    return results
        except Exception as e:
            log.error("Failed to fetch validation attempts", incident_id=incident_id, error=str(e))
            return []

    async def _get_forensic_snapshot(self, incident_id: str) -> Dict[str, Any]:
        """
        Fetch forensic snapshot from the collector if available.
        Returns empty dict if no collector registered or no snapshot exists.
        """
        if not self._forensic_collector:
            return {}

        try:
            snapshot = await self._forensic_collector.get_live_snapshot(incident_id)
            return snapshot or {}
        except Exception as e:
            log.error("Failed to fetch forensic snapshot", incident_id=incident_id, error=str(e))
            return {}

    # ================================================================
    # DERIVED / COMPUTED FIELDS
    # ================================================================

    def _assess_criticality(self, incident: Dict[str, Any]) -> Dict[str, Any]:
        """Assess asset criticality based on namespace and resource."""
        namespace = incident.get("namespace", "default")
        resource = incident.get("resource", "")

        critical_namespaces = {"production", "prod", "kube-system", "istio-system"}
        critical_resource_keywords = ["database", "db", "api", "gateway", "auth"]

        score = 5
        reasons = []

        if namespace in critical_namespaces:
            score += 3
            reasons.append(f"Critical namespace: {namespace}")

        for keyword in critical_resource_keywords:
            if keyword in resource.lower():
                score += 2
                reasons.append(f"Critical resource type: {keyword}")
                break

        score = min(score, 10)
        return {
            "score": score,
            "level": "critical" if score >= 8 else "high" if score >= 6 else "medium",
            "reasons": reasons,
        }

    def _build_retry_history(self, action_attempts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Build a clean retry history from action_attempts.
        Each entry summarises one execute-validate cycle and why it failed.
        """
        history = []

        for attempt in action_attempts:
            # Only include failed or partially-failed attempts
            all_passed = (
                attempt.get("phase1_success") and
                attempt.get("phase2_success") and
                attempt.get("phase3_success")
            )

            entry = {
                "attempt_id": attempt.get("id"),
                "action_type": attempt.get("action_type"),
                "strategy_level": attempt.get("strategy_level", 1),
                "attempt_number": attempt.get("attempt_number", 1),
                "parent_attempt_id": attempt.get("parent_attempt_id"),
                "status": attempt.get("status"),
                "executed_at": attempt.get("executed_at"),
                "phases": {
                    "phase1": {
                        "success": bool(attempt.get("phase1_success")),
                        "message": attempt.get("phase1_message"),
                        "validated_at": attempt.get("phase1_validated_at"),
                    },
                    "phase2": {
                        "success": bool(attempt.get("phase2_success")),
                        "message": attempt.get("phase2_message"),
                        "validated_at": attempt.get("phase2_validated_at"),
                    },
                    "phase3": {
                        "success": bool(attempt.get("phase3_success")),
                        "message": attempt.get("phase3_message"),
                        "validated_at": attempt.get("phase3_validated_at"),
                    },
                },
                "all_phases_passed": all_passed,
                "fallback_triggered": bool(attempt.get("fallback_triggered")),
                "fallback_reason": attempt.get("fallback_reason"),
            }

            # Summarise why this attempt failed
            if not all_passed:
                failure_points = []
                for phase_key in ("phase1", "phase2", "phase3"):
                    phase = entry["phases"][phase_key]
                    if not phase["success"] and phase["message"]:
                        failure_points.append(f"{phase_key}: {phase['message']}")
                entry["failure_summary"] = "; ".join(failure_points) if failure_points else "Unknown failure"

            history.append(entry)

        return history

    def _build_containment_summary(
        self,
        actions: List[Dict[str, Any]],
        action_attempts: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Summarise the current state of containment for quick Decision Agent consumption.
        """
        total_actions = len(actions)
        successful_actions = sum(
            1 for a in actions if a.get("status") in ("completed", "success", "verified")
        )

        total_attempts = len(action_attempts)
        fully_validated = sum(
            1 for a in action_attempts
            if a.get("phase1_success") and a.get("phase2_success") and a.get("phase3_success")
        )

        failed_attempts = [
            a for a in action_attempts
            if not (a.get("phase1_success") and a.get("phase2_success") and a.get("phase3_success"))
        ]

        # What action types have been tried
        tried_action_types = list({a.get("action_type") for a in action_attempts})

        return {
            "total_actions_queued": total_actions,
            "successful_actions": successful_actions,
            "total_attempts": total_attempts,
            "fully_validated_attempts": fully_validated,
            "failed_attempts_count": len(failed_attempts),
            "tried_action_types": tried_action_types,
            "containment_achieved": fully_validated > 0,
            "latest_failure": failed_attempts[-1].get("fallback_reason") if failed_attempts else None,
        }

    # ================================================================
    # CONVENIENCE METHODS FOR AGENTS
    # ================================================================

    async def get_context_for_decision(self, incident_id: str, retry_number: int = 0) -> Dict[str, Any]:
        """
        Returns context shaped for the Decision Agent.
        Includes retry count so Decision Agent knows to escalate strategy.
        Refreshes context to ensure latest validation results are included.
        """
        context = await self.refresh_context(incident_id)
        context["decision_context"] = {
            "retry_number": retry_number,
            "is_retry": retry_number > 0,
            "failed_action_types": context["containment_summary"]["tried_action_types"],
            "previous_failures": context["retry_history"],
            "recommendation": (
                "escalate_strategy" if retry_number > 0 else "initial_containment"
            ),
        }
        return context

    async def get_context_for_investigation(self, incident_id: str) -> Dict[str, Any]:
        """
        Returns context shaped for the Investigation Agent.
        Includes full forensic snapshot, IOC-relevant data, and timeline anchor points.
        """
        context = await self.refresh_context(incident_id)
        context["investigation_context"] = {
            "has_live_forensics": context["has_live_forensics"],
            "data_quality": "excellent" if context["has_live_forensics"] else "standard",
            "containment_summary": context["containment_summary"],
            "incident_type": context["incident"].get("type"),
            "resource": context["incident"].get("resource"),
            "severity": context["incident"].get("severity"),
        }
        return context


# ================================================================
# MODULE-LEVEL SINGLETON
# ================================================================

context_agent = ContextAgent()