"""
Decision Agent - LLM-Powered Containment Decisions

Determines WHAT actions to take and WHETHER to auto-execute or require approval.
Absorbs the Progressive Trust Engine.

Called in two ways:
1. Via 'decision' queue - after triage (retry_number=0)
2. Directly via decide() - by Validation Agent on retry (retry_number > 0)

On first call: LLM selects best actions from ActionRegistry given full incident context.
On retry: LLM reads containment phase_updates (what actions ran, what messages they gave)
          and either detects success-via-prior-action or escalates to a new strategy.

Both paths produce the same output: actions pushed to 'containment' queue.
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import structlog

from config import config
from core import (
    queue, llm_client, get_trust_metrics, update_trust_metrics, save_action_history,
    get_similar_actions, save_action, update_incident, ActionMode,
    TrustLevel, IncidentStatus, get_incident
)
from core.actions import ActionRegistry
from agents.context import context_agent

log = structlog.get_logger()


@dataclass
class TrustLevelConfig:
    name: str
    confidence_threshold: Optional[float]
    action_range: tuple
    requires_approval_for_p1: bool


TRUST_LEVELS = {
    1: TrustLevelConfig("Learning",   None, (0, 50),             True),
    2: TrustLevelConfig("Cautious",   0.95, (51, 150),           True),
    3: TrustLevelConfig("Confident",  0.90, (151, 500),          False),
    4: TrustLevelConfig("Autonomous", 0.85, (501, float('inf')), False),
}


@dataclass
class DecisionResult:
    """Structured result returned by decide(). Used by Validation Agent."""
    incident_id: str
    action_mode: ActionMode
    actions: List[Dict[str, Any]]
    trust_level: int
    confidence: float
    reason: str


class ApprovalManager:
    """Manages action approvals via Redis signal."""

    def __init__(self):
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.approval_timeout = 300  # 5 minutes

    async def request_approval(self, action_data: Dict[str, Any]) -> bool:
        action_id = action_data.get("action_id")
        incident_id = action_data.get("incident_id")

        self.pending_approvals[action_id] = {
            **action_data,
            "requested_at": datetime.utcnow().isoformat(),
        }

        await queue.push("notification", {
            "type": "action_pending",
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_data.get("action_type"),
            "severity": action_data.get("severity", "P3"),
            "action_details": str(action_data.get("params", {})),
            "summary": f"Approval required for {action_data.get('action_type')}",
        })

        log.info("Approval requested", action_id=action_id, incident_id=incident_id)
        return await self._wait_for_approval(action_id)

    async def _wait_for_approval(self, action_id: str, timeout: int = None) -> bool:
        timeout = timeout or self.approval_timeout
        start = datetime.utcnow()

        while (datetime.utcnow() - start).seconds < timeout:
            try:
                approval = await queue.pop_nowait(f"approval:{action_id}")
                if approval:
                    approved = approval.get("approved", False)
                    self.pending_approvals.pop(action_id, None)
                    return approved
            except Exception:
                pass
            await asyncio.sleep(1)

        log.warning("Approval timeout", action_id=action_id)
        self.pending_approvals.pop(action_id, None)
        return False

    async def approve(self, action_id: str, approved_by: str = "analyst"):
        await queue.push(f"approval:{action_id}", {
            "approved": True,
            "approved_by": approved_by,
            "approved_at": datetime.utcnow().isoformat(),
        })

    async def reject(self, action_id: str, rejected_by: str = "analyst", reason: str = ""):
        await queue.push(f"approval:{action_id}", {
            "approved": False,
            "rejected_by": rejected_by,
            "reason": reason,
            "rejected_at": datetime.utcnow().isoformat(),
        })


class DecisionAgent:
    """
    Decision Agent - LLM selects actions, trust engine decides auto vs approval.

    First call (retry_number=0):
      - Pull full context via context_agent
      - LLM selects best actions from registered ActionRegistry executors
      - Trust engine decides auto vs approval

    Retry (retry_number > 0):
      - Read containment phase_updates: the actual messages from failed/succeeded actions
      - LLM sees "Container not found" → knows container is already gone → signals success
      - LLM sees "permission denied" → recommends a different registered action
    """

    def __init__(self):
        self.approval_manager = ApprovalManager()
        self.running = False

    # ================================================================
    # QUEUE LISTENER
    # ================================================================

    async def start(self):
        self.running = True
        metrics = await get_trust_metrics()
        level = metrics.get("current_level", 1)
        available_actions = ActionRegistry.list_available()
        log.info("Decision Agent started",
                 trust_level=level,
                 trust_level_name=TRUST_LEVELS[level].name,
                 available_actions=available_actions)
        await self._decision_loop()

    async def stop(self):
        self.running = False
        log.info("Decision Agent stopped")

    async def _decision_loop(self):
        while self.running:
            try:
                request = await queue.pop("decision", timeout=5)
                if request:
                    await self._process_decision_request(request)
            except Exception as e:
                log.error("Error in decision loop", error=str(e))
                await asyncio.sleep(1)

    async def _process_decision_request(self, request: Dict[str, Any]):
        incident_id = request.get("incident_id")
        severity = request.get("severity", "P3")
        confidence = request.get("confidence", 0.5)
        retry_number = request.get("retry_number", 0)

        log.info("Processing decision",
                 incident_id=incident_id,
                 severity=severity,
                 confidence=confidence,
                 retry_number=retry_number)

        full_context = await context_agent.get_context_for_decision(
            incident_id, retry_number=retry_number
        )

        result = await self.decide(
            incident_id=incident_id,
            severity=severity,
            confidence=confidence,
            context=full_context,
            retry_number=retry_number,
        )

        metrics = await get_trust_metrics()
        await self._check_level_change(metrics)

        log.info("Decision made",
                 incident_id=incident_id,
                 action_mode=result.action_mode.value,
                 trust_level=result.trust_level,
                 actions_count=len(result.actions),
                 reason=result.reason)

    # ================================================================
    # CORE DECIDE METHOD (reusable by Validation Agent)
    # ================================================================

    async def decide(
        self,
        incident_id: str,
        severity: str,
        confidence: float,
        context: Optional[Dict[str, Any]] = None,
        retry_number: int = 0,
        actions: Optional[List[Dict[str, Any]]] = None,  # kept for API compat, ignored
    ) -> DecisionResult:
        """
        Make a containment decision using LLM + trust engine.

        First call (retry_number=0):
          LLM selects best actions from registered executors given incident context.

        Retry (retry_number > 0):
          LLM reads the containment phase_updates which contain the actual error messages
          from every action that already ran. This is the key signal:
          - "Container not found" on delete_pod → container already deleted → SUCCEEDED
          - "Container not found" on network_isolate after delete_pod ran → same thing
          - "permission denied" → try a different approach
        """
        if context is None:
            context = await context_agent.get_context_for_decision(
                incident_id, retry_number=retry_number
            )

        metrics = await get_trust_metrics()
        current_level = metrics.get("current_level", 1)
        level_config = TRUST_LEVELS[current_level]

        registered_actions = ActionRegistry.list_available()
        capabilities = ActionRegistry.get_capabilities()

        if retry_number > 0:
            selected_actions, already_succeeded = await self._select_actions_for_retry(
                context=context,
                registered_actions=registered_actions,
                capabilities=capabilities,
                retry_number=retry_number,
            )

            if already_succeeded:
                log.info("LLM determined containment already succeeded",
                         incident_id=incident_id, retry_number=retry_number)
                return DecisionResult(
                    incident_id=incident_id,
                    action_mode=ActionMode.AUTO,
                    actions=[],
                    trust_level=current_level,
                    confidence=confidence,
                    reason="Containment already succeeded (detected via failure message analysis)",
                )
        else:
            selected_actions = await self._select_actions_initial(
                context=context,
                registered_actions=registered_actions,
                capabilities=capabilities,
            )

        if not selected_actions:
            log.warning("LLM returned no actions, falling back",
                        incident_id=incident_id)
            selected_actions = self._fallback_actions(registered_actions)

        action_mode, reason = await self._determine_mode(
            current_level, level_config, severity, confidence,
            selected_actions, retry_number=retry_number,
        )

        if action_mode == ActionMode.AUTO:
            await self._execute_auto(incident_id, selected_actions, confidence, severity)
        else:
            await self._request_approval(incident_id, selected_actions, severity)

        return DecisionResult(
            incident_id=incident_id,
            action_mode=action_mode,
            actions=selected_actions,
            trust_level=current_level,
            confidence=confidence,
            reason=reason,
        )

    # ================================================================
    # LLM ACTION SELECTION
    # ================================================================

    async def _select_actions_initial(
        self,
        context: Dict[str, Any],
        registered_actions: List[str],
        capabilities: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """First-time action selection. LLM picks from registered executors."""
        incident = context.get("incident", {})
        mitre = context.get("mitre_mapping", {})
        criticality = context.get("asset_criticality", {})
        forensics = context.get("forensic_snapshot", {})
        similar_root_causes = context.get("similar_incident_root_causes", [])
        # phase_updates[phase] is a list of dicts (update_context appends each call)
        # Use [-1] for latest entry
        triage_history = context.get("phase_updates", {}).get("triage", [])
        triage_update = triage_history[-1] if triage_history else {}

        action_descriptions = {
            name: {
                "description": cap.description,
                "destructive": cap.destructive,
                "reversible": cap.reversible,
                "min_trust_level": cap.min_trust_level,
            }
            for name, cap in capabilities.items()
        }

        pipeline_history = self._build_pipeline_history(context, retry_number=0)

        try:
            result = await llm_client.select_containment_actions(
                incident=incident,
                mitre_mapping=mitre,
                asset_criticality=criticality,
                forensic_snapshot=forensics,
                triage_summary=triage_update.get("llm_summary", ""),
                available_actions=action_descriptions,
                pipeline_history=pipeline_history,
                similar_incident_root_causes=similar_root_causes,
            )

            actions = result.get("actions", [])
            validated = self._validate_action_list(actions, registered_actions)

            log.info("LLM selected initial actions",
                     incident_id=incident.get("id"),
                     selected=[a.get("action") for a in validated],
                     reasoning=result.get("reasoning", "")[:100])

            return validated

        except Exception as e:
            log.error("LLM action selection failed, using fallback",
                      incident_id=incident.get("id"), error=str(e))
            return self._fallback_actions(registered_actions)

    async def _select_actions_for_retry(
        self,
        context: Dict[str, Any],
        registered_actions: List[str],
        capabilities: Dict[str, Any],
        retry_number: int,
    ) -> tuple[List[Dict[str, Any]], bool]:
        """
        Retry action selection. LLM reads all execution and validation outcomes so far.

        Sources of failure data (checked in this order, all included):
        1. validation phase_updates — written by ValidationService before calling decide().
           THIS IS THE CRITICAL SOURCE for the case where an action SUCCEEDED at execution
           time but then the container disappeared before Phase 2 ran (e.g. user deleted it,
           or a prior action like delete_pod already removed it).
           Message: "Cannot verify - container inspect failed" → container is gone → SUCCESS
        2. containment phase_updates.actions_taken — written by ContainmentAgent after every
           execution. Has the exact precondition/runtime errors for failed actions.
           Message: "Container not found: X" on pause/delete → already gone → SUCCESS
        3. DB retry_history — fallback if in-memory cache is cold.

        The LLM uses all three to distinguish:
        - Validation "Cannot verify - container inspect failed" → container gone → SUCCESS
        - Execution "Container not found" on delete/isolate → already gone → SUCCESS
        - Execution "permission denied" → wrong approach, try different action
        """
        incident = context.get("incident", {})
        phase_updates = context.get("phase_updates", {})

        # Source 1: validation phase_updates (KEY — covers the case where execution
        # succeeded but container vanished before Phase 2)
        # phase_updates["validation"] is a list of dicts — one entry per retry cycle
        validation_history = phase_updates.get("validation", [])
        validation_failures = [
            {
                "action_type": v.get("last_failed_action", "unknown"),
                "phase": v.get("last_failure_phase", "phase2"),
                "message": v.get("last_failure_message"),
                "retry_number": v.get("retry_number"),
                "success": False,
                "source": "ivam_validation",
            }
            for v in validation_history
            if isinstance(v, dict) and v.get("last_failure_message")
        ]

        # Source 2: in-memory containment phase updates (fast path — written right after execution)
        # phase_updates["containment"] is a list of dicts — one entry per execution
        containment_history = phase_updates.get("containment", [])
        actions_taken = []
        for entry in containment_history:
            if isinstance(entry, dict):
                actions_taken.extend(entry.get("actions_taken", []))

        # Source 3: DB actions table — used when in-memory cache is cold (e.g. 5-min Phase 2 delay)
        # This is the most reliable persistent source: always populated after containment runs
        db_actions = context.get("actions", [])
        if not actions_taken and db_actions:
            # Reconstruct outcomes from DB records as best we can
            actions_taken = [
                {
                    "action_type": a.get("action_type"),
                    "success": a.get("status") in ("success", "auto_approved", "approved"),
                    "status": a.get("status"),
                    "message": a.get("result") or a.get("status"),
                    "error": None,
                    "source": "db_actions",
                }
                for a in db_actions if isinstance(a, dict)
            ]
            log.debug("In-memory cache cold — using DB actions as fallback",
                      incident_id=incident.get("id"),
                      db_actions_count=len(actions_taken))

        # Build all_outcomes: every action that ran regardless of success/fail
        # The LLM needs the full picture to reason about what happened
        all_outcomes = [
            {
                "action_type": a.get("action_type"),
                "success": a.get("success"),
                "status": a.get("status"),
                "message": a.get("message"),
                "error": a.get("error"),
                "source": a.get("source", "containment_execution"),
            }
            for a in actions_taken
            if isinstance(a, dict)
        ]

        # Source 4: DB retry history (action_attempts table)
        retry_history = context.get("retry_history", [])
        db_retry = [
            {
                "action_type": a.get("action_type"),
                "failure_summary": a.get("failure_summary"),
                "all_phases_passed": a.get("all_phases_passed"),
                "source": "db_retry_history",
            }
            for a in retry_history if isinstance(a, dict)
        ]

        # Combine: validation failures first (most diagnostic), then all execution outcomes,
        # then DB retry history. The LLM receives ALL of this as "prior_attempts" context.
        prior_attempts = validation_failures + all_outcomes + db_retry

        # If we have absolutely nothing (very first retry, cold cache, no DB records)
        # fall through to fresh action selection
        if not prior_attempts:
            log.warning("No prior attempt data available — selecting fresh actions",
                        incident_id=incident.get("id"))
            actions = await self._select_actions_initial(context, registered_actions, capabilities)
            return actions, False

        # What has already been tried — exclude these from recommendations
        tried_types = set(filter(None,
            [a.get("action_type") for a in actions_taken if isinstance(a, dict)]
            + [v.get("last_failed_action") for v in validation_history if isinstance(v, dict) and v.get("last_failed_action")]
            + context.get("containment_summary", {}).get("tried_action_types", [])
        ))
        untried = [a for a in registered_actions if a not in tried_types] or registered_actions

        pipeline_history = self._build_pipeline_history(context, retry_number=retry_number)

        log.debug("Retry context for LLM",
                  incident_id=incident.get("id"),
                  validation_failures=len(validation_failures),
                  all_outcomes=len(all_outcomes),
                  db_retry=len(db_retry),
                  prior_attempts_total=len(prior_attempts),
                  tried_types=list(tried_types),
                  untried=untried,
                  cache_cold=not containment_history)

        try:
            analysis = await llm_client.analyze_containment_failure(
                incident=incident,
                failed_attempts=prior_attempts,
                available_actions=untried,
                pipeline_history=pipeline_history,
            )

            log.info("LLM failure analysis",
                     incident_id=incident.get("id"),
                     containment_already_succeeded=analysis.get("containment_already_succeeded"),
                     recommended_action=analysis.get("recommended_action"),
                     reason=analysis.get("reason"))

            if analysis.get("containment_already_succeeded"):
                return [], True

            recommended = analysis.get("recommended_action")
            if recommended:
                if recommended not in registered_actions:
                    log.warning("LLM recommended unregistered action, ignoring",
                                recommended=recommended,
                                registered=registered_actions)
                else:
                    action = {
                        "action": recommended,
                        "params": analysis.get("recommended_params", {}),
                        "priority": 1,
                        "reason": analysis.get("reasoning", "LLM escalation"),
                        "llm_escalated": True,
                        "retry_number": retry_number,
                    }
                    return [action], False

        except Exception as e:
            log.error("LLM failure analysis failed, using rule-based fallback",
                      incident_id=incident.get("id"), error=str(e))

        # Rule-based fallback: try anything not yet attempted
        escalated = [
            {"action": a, "params": {}, "priority": 1, "reason": "Rule-based escalation"}
            for a in registered_actions if a not in tried_types
        ]
        if escalated:
            return escalated[:1], False

        # Everything already tried — resubmit with escalation flag
        return [
            {"action": a, "params": {}, "escalated": True, "retry_number": retry_number}
            for a in registered_actions
        ], False

    def _validate_action_list(
        self,
        actions: List[Dict[str, Any]],
        registered_actions: List[str],
    ) -> List[Dict[str, Any]]:
        """Filter out any actions the LLM hallucinated that aren't in the registry."""
        valid, invalid = [], []
        for action in actions:
            name = action.get("action")
            if name in registered_actions:
                valid.append(action)
            else:
                invalid.append(name)
        if invalid:
            log.warning("LLM recommended unregistered actions, filtered",
                        invalid=invalid, kept=[a.get("action") for a in valid])
        return valid

    def _fallback_actions(self, registered_actions: List[str]) -> List[Dict[str, Any]]:
        """Last-resort fallback when LLM fails entirely."""
        if "capture_logs" in registered_actions:
            return [{"action": "capture_logs", "params": {"duration": 300},
                     "priority": 1, "reason": "Fallback: gather evidence"}]
        if registered_actions:
            caps = ActionRegistry.get_capabilities()
            non_destructive = [
                a for a in registered_actions
                if not getattr(caps.get(a), "destructive", True)
            ]
            target = non_destructive[0] if non_destructive else registered_actions[0]
            return [{"action": target, "params": {}, "priority": 1,
                     "reason": "Fallback: only available action"}]
        return []

    def _build_pipeline_history(self, context: Dict[str, Any], retry_number: int) -> Dict[str, Any]:
        """
        Build a structured pipeline history dict summarising what happened across
        all pipeline stages. phase_updates[phase] is always a list of dicts
        (update_context appends); use [-1] for the latest entry.
        """
        phase_updates = context.get("phase_updates", {})

        # Each phase stores a list; get latest entry with [-1]
        triage_h = phase_updates.get("triage", [])
        decision_h = phase_updates.get("decision", [])
        containment_h = phase_updates.get("containment", [])
        validation_h = phase_updates.get("validation", [])

        triage = triage_h[-1] if triage_h else {}
        decision = decision_h[-1] if decision_h else {}
        containment = containment_h[-1] if containment_h else {}
        validation = validation_h[-1] if validation_h else {}

        # Flatten all actions_taken across every containment entry (in-memory)
        all_actions_taken = []
        for entry in containment_h:
            if isinstance(entry, dict):
                all_actions_taken.extend(entry.get("actions_taken", []))

        # Fall back to DB actions when in-memory cache is cold (e.g. after 5-min Phase 2 delay)
        if not all_actions_taken:
            for a in context.get("actions", []):
                if isinstance(a, dict):
                    all_actions_taken.append({
                        "action_type": a.get("action_type"),
                        "success": a.get("status") in ("success", "auto_approved", "approved"),
                        "message": a.get("result") or a.get("status"),
                        "source": "db_actions",
                    })

        return {
            "retry_number": retry_number,
            "triage": {
                "severity": triage.get("severity"),
                "confidence": triage.get("confidence"),
                "summary": triage.get("llm_summary", ""),
            },
            "decision": {
                "action_mode": decision.get("action_mode"),
                "actions_queued": decision.get("actions_queued", 0),
                "resource": decision.get("resource"),
            },
            "containment": {
                "actions_taken": all_actions_taken,
                "last_action_type": containment.get("last_action_type"),
                "last_action_success": containment.get("last_action_success"),
                "last_action_message": containment.get("last_action_message"),
            },
            "validation": {
                "all_failures": [
                    {
                        "phase": v.get("last_failure_phase"),
                        "message": v.get("last_failure_message"),
                        "action": v.get("last_failed_action"),
                    }
                    for v in validation_h if isinstance(v, dict)
                ],
                "last_failure_phase": validation.get("last_failure_phase"),
                "last_failure_message": validation.get("last_failure_message"),
                "last_failed_action": validation.get("last_failed_action"),
            },
        }

    # ================================================================
    # TRUST ENGINE: AUTO vs APPROVAL
    # ================================================================

    async def _determine_mode(
        self,
        current_level: int,
        level_config: TrustLevelConfig,
        severity: str,
        confidence: float,
        actions: List[Dict],
        retry_number: int = 0,
    ) -> tuple[ActionMode, str]:
        if current_level == 1:
            return ActionMode.APPROVAL_REQUIRED, "Trust level 1 (Learning): all actions require approval"

        if severity == "P1" and level_config.requires_approval_for_p1:
            return ActionMode.APPROVAL_REQUIRED, f"P1 severity requires approval at trust level {current_level}"

        threshold = level_config.confidence_threshold
        if threshold and retry_number > 0:
            threshold = max(threshold - 0.05, 0.70)

        if threshold and confidence < threshold:
            return (
                ActionMode.APPROVAL_REQUIRED,
                f"Confidence {confidence:.2f} below threshold {threshold:.2f}",
            )

        for action in actions:
            similar = await get_similar_actions(action.get("action", "unknown"))
            if similar:
                success_count = sum(1 for a in similar if a.get("success"))
                success_rate = success_count / len(similar)
                if success_rate < 0.95:
                    return (
                        ActionMode.APPROVAL_REQUIRED,
                        f"Low historical success rate ({success_rate:.0%}) for {action.get('action')}",
                    )

        return (
            ActionMode.AUTO,
            f"Trust level {current_level} ({level_config.name}): confidence {confidence:.2f} meets threshold",
        )

    # ================================================================
    # EXECUTION
    # ================================================================

    def _generate_action_id(self, incident_id: str, action_type: str) -> str:
        timestamp = int(datetime.utcnow().timestamp() * 1000) % 10000
        short_uuid = str(uuid.uuid4())[:8]
        return f"act-{incident_id[:4]}-{action_type[:4]}-{timestamp}-{short_uuid}"

    async def _safe_save_action(self, action_data: Dict[str, Any], max_retries: int = 3) -> bool:
        for attempt in range(max_retries):
            try:
                await save_action(action_data)
                return True
            except Exception as e:
                if "unique constraint failed" in str(e).lower():
                    old_id = action_data.get("id")
                    new_id = self._generate_action_id(
                        action_data.get("incident_id", "unknown"),
                        action_data.get("action_type", "unknown"),
                    )
                    action_data["id"] = new_id
                    action_data["action_id"] = new_id
                    log.warning("Action ID collision, retrying", old_id=old_id, new_id=new_id)
                    continue
                log.error("Failed to save action", error=str(e))
                return False
        return False

    async def _execute_auto(
        self,
        incident_id: str,
        actions: List[Dict],
        confidence: float,
        severity: str,
    ):
        await update_incident(incident_id, {"status": IncidentStatus.CONTAINMENT.value})

        incident = await get_incident(incident_id)
        if not incident:
            log.error("Incident not found for auto-execution", incident_id=incident_id)
            return

        resource = incident.get("resource", "unknown")
        namespace = incident.get("namespace", "docker")
        saved = 0

        for action in actions:
            action_id = self._generate_action_id(incident_id, action.get("action", "unknown"))
            action_data = {
                "id": action_id,
                "incident_id": incident_id,
                "action_type": action.get("action"),
                "params": action.get("params", {}),
                "status": "auto_approved",
                "resource": resource,
                "namespace": namespace,
            }

            if await self._safe_save_action(action_data):
                saved += 1
                await queue.push("containment", {
                    **action_data,
                    "action_id": action_id,
                    "confidence": confidence,
                    "auto_approved": True,
                })

        context_agent.update_context(incident_id, "decision", {
            "action_mode": "AUTO",
            "actions_queued": saved,
            "resource": resource,
        })

        await queue.push("notification", {
            "type": "actions_auto_approved",
            "incident_id": incident_id,
            "severity": severity,
            "actions_count": saved,
            "summary": f"Auto-executing {saved}/{len(actions)} containment actions on {resource}",
        })

    async def _request_approval(self, incident_id: str, actions: List[Dict], severity: str):
        await update_incident(incident_id, {"status": IncidentStatus.PENDING_APPROVAL.value})

        incident = await get_incident(incident_id)
        if not incident:
            log.error("Incident not found for approval", incident_id=incident_id)
            return

        resource = incident.get("resource", "unknown")
        namespace = incident.get("namespace", "docker")
        saved = 0

        for action in actions:
            action_id = self._generate_action_id(incident_id, action.get("action", "unknown"))
            action_data = {
                "id": action_id,
                "action_id": action_id,
                "incident_id": incident_id,
                "action_type": action.get("action"),
                "params": action.get("params", {}),
                "status": "pending_approval",
                "severity": severity,
                "resource": resource,
                "namespace": namespace,
            }

            if await self._safe_save_action(action_data):
                saved += 1
                asyncio.create_task(self._handle_approval(action_data))

        context_agent.update_context(incident_id, "decision", {
            "action_mode": "APPROVAL_REQUIRED",
            "actions_pending_approval": saved,
            "resource": resource,
        })

    async def _handle_approval(self, action_data: Dict[str, Any]):
        approved = await self.approval_manager.request_approval(action_data)

        if approved:
            await queue.push("containment", {
                **action_data,
                "status": "approved",
                "auto_approved": False,
            })
            await queue.push("notification", {
                "type": "action_approved",
                "incident_id": action_data.get("incident_id"),
                "action_id": action_data.get("action_id"),
                "severity": "P3",
                "summary": f"Action {action_data.get('action_type')} approved",
            })
        else:
            incident_id = action_data.get("incident_id")
            action_type = action_data.get("action_type")
            action_id = action_data.get("action_id")

            await queue.push("notification", {
                "type": "action_rejected",
                "incident_id": incident_id,
                "action_id": action_id,
                "severity": "P3",
                "summary": f"Action {action_type} rejected/timed out",
            })

            # Update context so Decision Agent knows this action was rejected
            context_agent.update_context(incident_id, "containment", {
                "actions_taken": [{
                    "action_type": action_type,
                    "success": False,
                    "status": "rejected",
                    "message": f"Action {action_type} rejected or timed out awaiting approval",
                    "error": "approval_rejected",
                    "resource": action_data.get("resource"),
                    "executed_at": datetime.utcnow().isoformat(),
                }]
            })

            # Treat rejection as a validation failure to trigger the retry loop.
            # Decision Agent will re-evaluate: either pick a different action
            # or escalate strategy based on what has been tried.
            await queue.push("validation", {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "resource": action_data.get("resource", "unknown"),
                "rejected": True,
                "result": {
                    "success": False,
                    "status": "rejected",
                    "verified_immediate": False,
                    "message": f"Action {action_type} was rejected or timed out",
                },
            })

            log.info("Action rejected — triggering validation retry loop",
                     incident_id=incident_id, action_type=action_type)

    # ================================================================
    # TRUST LEVEL MANAGEMENT
    # ================================================================

    async def record_action_result(
        self,
        action_type: str,
        incident_type: str,
        success: bool,
        confidence: float,
        analyst_rating: int = None,
        feedback: str = None,
    ):
        await save_action_history({
            "action_type": action_type,
            "incident_type": incident_type,
            "success": success,
            "confidence": confidence,
            "analyst_rating": analyst_rating,
            "feedback": feedback,
        })

        metrics = await get_trust_metrics()
        updates = {"total_actions": metrics.get("total_actions", 0) + 1}
        if success:
            updates["successful_actions"] = metrics.get("successful_actions", 0) + 1
        else:
            updates["failed_actions"] = metrics.get("failed_actions", 0) + 1
        await update_trust_metrics(updates)

    async def _check_level_change(self, metrics: Dict[str, Any]):
        current_level = metrics.get("current_level", 1)
        total_actions = metrics.get("total_actions", 0)
        successful_actions = metrics.get("successful_actions", 0)
        success_rate = successful_actions / total_actions if total_actions > 0 else 0

        if current_level < 4:
            next_config = TRUST_LEVELS[current_level + 1]
            min_actions, _ = next_config.action_range
            if total_actions >= min_actions and success_rate >= 0.95:
                await self._set_level(current_level + 1, "Level up: success rate >= 95%")

        if current_level > 1 and success_rate < 0.90:
            await self._set_level(current_level - 1, "Level down: success rate below 90%")

    async def _set_level(self, new_level: int, reason: str):
        level_config = TRUST_LEVELS[new_level]
        await update_trust_metrics({
            "current_level": new_level,
            "level_changed_at": datetime.utcnow().isoformat(),
        })
        log.info("Trust level changed", new_level=new_level,
                 name=level_config.name, reason=reason)
        await queue.push("notification", {
            "type": "trust_level_changed",
            "severity": "P4" if "up" in reason else "P2",
            "new_level": new_level,
            "level_name": level_config.name,
            "reason": reason,
            "summary": f"Trust level → {new_level} ({level_config.name}): {reason}",
        })


# Agent instance
decision_agent = DecisionAgent()