"""
Validation Service - IVAM Phase 2 & 3 + Retry Loop Owner

This service owns the full execute-validate retry cycle:
1. Run Phase 2 (sustained) + Phase 3 (effective) validation
2. On failure → get context → call Decision Agent with retry_number
3. Decision Agent either:
   a. Detects containment already succeeded → pass to Investigation
   b. Recommends new action → Containment Agent executes it → back to step 1
4. After MAX_RETRIES exhausted → send email notification → pass to Investigation
   (marked as partially_contained)

Investigation Agent always runs regardless of containment outcome.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, Optional
import structlog

from config import config
from core import queue, update_incident, IncidentStatus
from core.actions import ActionRegistry, ActionResult
from agents.context import context_agent

log = structlog.get_logger()

MAX_RETRIES = 3  # Max execute-validate cycles before giving up


class ValidationService:
    """
    Validation Service - owns IVAM Phase 2/3 and the containment retry loop.
    """

    def __init__(self):
        self.running = False
        self.validation_count = 0
        self.phase2_failures = 0
        self.phase3_failures = 0
        # Track retry counts per incident in memory
        # key: incident_id, value: retry_number (how many full cycles done)
        self._retry_counts: Dict[str, int] = {}

    async def start(self):
        self.running = True
        log.info("Validation Service started", max_retries=MAX_RETRIES)
        await self._validation_loop()

    async def stop(self):
        self.running = False
        log.info("Validation Service stopped",
                 total_validations=self.validation_count,
                 phase2_failures=self.phase2_failures,
                 phase3_failures=self.phase3_failures)

    async def _validation_loop(self):
        while self.running:
            try:
                validation_request = await queue.pop("validation", timeout=5)
                if validation_request:
                    # Run in background so queue stays responsive
                    asyncio.create_task(self._process_validation(validation_request))
            except Exception as e:
                log.error("Error in validation loop", error=str(e))
                await asyncio.sleep(1)

    async def _process_validation(self, request: Dict[str, Any]):
        """Run Phase 2 + Phase 3 for one action. On failure, trigger retry loop."""
        incident_id = request.get("incident_id")
        action_id = request.get("action_id")
        action_type = request.get("action_type")
        resource = request.get("resource")
        result_dict = request.get("result", {})

        log.info("Starting Phase 2+3 validation",
                 incident_id=incident_id,
                 action_id=action_id,
                 action_type=action_type)

        self.validation_count += 1

        # Action was rejected/timed out at approval stage — skip Phase 2/3,
        # go straight to retry loop so Decision Agent can pick a different action.
        if request.get("rejected"):
            log.warning("Action was rejected — triggering retry loop",
                        incident_id=incident_id, action_type=action_type)
            await self._handle_validation_failure(
                incident_id, action_id, action_type, resource,
                phase="phase1", failure_message=f"Action {action_type} rejected or timed out at approval",
            )
            return

        # Execution failed before reaching validation — context already has the failure
        # message from ContainmentAgent._update_context_after_execution.
        # Skip Phase 2/3, trigger retry loop so Decision Agent picks a different action.
        if request.get("execution_failed"):
            failure_message = request.get("failure_message") or f"Action {action_type} execution failed"
            log.warning("Action execution failed — triggering retry loop",
                        incident_id=incident_id, action_type=action_type,
                        failure_message=failure_message)
            await self._handle_validation_failure(
                incident_id, action_id, action_type, resource,
                phase="phase1", failure_message=failure_message,
            )
            return

        executor_class = ActionRegistry.get(action_type)
        if not executor_class:
            log.error("Unknown action type for validation", action_type=action_type)
            return

        try:
            executor = executor_class()
        except Exception as e:
            log.error("Failed to create executor for validation",
                      action_type=action_type, error=str(e))
            return

        try:
            result = ActionResult(**result_dict)
        except Exception as e:
            log.error("Failed to reconstruct ActionResult", error=str(e))
            return

        # ── Phase 2: Sustained ──────────────────────────────────────────
        try:
            phase2_success, phase2_msg = await executor.verify_sustained(resource, result)

            await self._save_validation_result(
                action_id, incident_id, "sustained", phase2_success, phase2_msg
            )
            await queue.push("notification", {
                "type": "validation_phase2",
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "phase": "sustained",
                "success": phase2_success,
                "message": phase2_msg,
            })

            if not phase2_success:
                self.phase2_failures += 1
                log.warning("Phase 2 failed", incident_id=incident_id,
                            action_id=action_id, reason=phase2_msg)
                await self._handle_validation_failure(
                    incident_id, action_id, action_type, resource,
                    phase="phase2", failure_message=phase2_msg,
                )
                return

        except Exception as e:
            log.error("Phase 2 error", incident_id=incident_id, error=str(e))
            self.phase2_failures += 1
            await self._handle_validation_failure(
                incident_id, action_id, action_type, resource,
                phase="phase2", failure_message=str(e),
            )
            return

        # ── Phase 3: Effective ──────────────────────────────────────────
        try:
            phase3_success, phase3_msg = await executor.verify_effective(resource, result)

            await self._save_validation_result(
                action_id, incident_id, "effective", phase3_success, phase3_msg
            )
            await queue.push("notification", {
                "type": "validation_phase3",
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "phase": "effective",
                "success": phase3_success,
                "message": phase3_msg,
            })

            if not phase3_success:
                self.phase3_failures += 1
                log.warning("Phase 3 failed", incident_id=incident_id,
                            action_id=action_id, reason=phase3_msg)
                await self._handle_validation_failure(
                    incident_id, action_id, action_type, resource,
                    phase="phase3", failure_message=phase3_msg,
                )
            else:
                # ✅ All phases passed
                log.info("All 3 validation phases passed",
                         incident_id=incident_id, action_id=action_id)
                self._retry_counts.pop(incident_id, None)  # Clean up retry state
                await self._pass_to_investigation(
                    incident_id, action_id, action_type, resource,
                    containment_status="confirmed",
                )

        except Exception as e:
            log.error("Phase 3 error", incident_id=incident_id, error=str(e))
            self.phase3_failures += 1
            await self._handle_validation_failure(
                incident_id, action_id, action_type, resource,
                phase="phase3", failure_message=str(e),
            )

    # ================================================================
    # RETRY LOOP
    # ================================================================

    async def _handle_validation_failure(
        self,
        incident_id: str,
        action_id: str,
        action_type: str,
        resource: str,
        phase: str,
        failure_message: str,
    ):
        """
        Central handler for validation failures.
        Increments retry counter and either calls Decision Agent or exhausts retries.
        """
        retry_number = self._retry_counts.get(incident_id, 0) + 1
        self._retry_counts[incident_id] = retry_number

        log.info("Handling validation failure",
                 incident_id=incident_id,
                 retry_number=retry_number,
                 max_retries=MAX_RETRIES,
                 phase=phase,
                 failure=failure_message)

        # Annotate context with this failure
        context_agent.update_context(incident_id, "validation", {
            "last_failure_phase": phase,
            "last_failure_message": failure_message,
            "last_failed_action": action_type,
            "retry_number": retry_number,
        })

        if retry_number > MAX_RETRIES:
            await self._retries_exhausted(incident_id, resource)
            return

        # Get enriched context for Decision Agent
        full_context = await context_agent.get_context_for_decision(
            incident_id, retry_number=retry_number
        )

        # Pull the original recommended actions from triage enrichment
        enriched = full_context.get("enriched", {})
        recommended_actions = enriched.get("recommended_actions", [])
        incident = full_context.get("incident", {})
        severity = incident.get("severity", "P3")
        confidence = enriched.get("confidence", 0.5)

        log.info("Calling Decision Agent for retry",
                 incident_id=incident_id,
                 retry_number=retry_number,
                 severity=severity,
                 confidence=confidence)

        # Import here to avoid circular import at module level
        from agents.decision_agent import decision_agent

        result = await decision_agent.decide(
            incident_id=incident_id,
            severity=severity,
            confidence=confidence,
            actions=recommended_actions,
            context=full_context,
            retry_number=retry_number,
        )

        # Decision Agent detected containment already succeeded
        if not result.actions and "already succeeded" in result.reason.lower():
            log.info("Decision Agent: containment already succeeded",
                     incident_id=incident_id, reason=result.reason)
            self._retry_counts.pop(incident_id, None)
            await self._pass_to_investigation(
                incident_id, action_id, action_type, resource,
                containment_status="succeeded_via_prior_action",
            )
            return

        # Decision Agent queued new actions to containment — they'll come back
        # through the validation queue when containment agent finishes
        log.info("Decision Agent queued new containment actions",
                 incident_id=incident_id,
                 retry_number=retry_number,
                 actions_queued=len(result.actions))

        await queue.push("notification", {
            "type": "containment_retry",
            "incident_id": incident_id,
            "severity": severity,
            "retry_number": retry_number,
            "max_retries": MAX_RETRIES,
            "failed_phase": phase,
            "failure_message": failure_message,
            "new_action_mode": result.action_mode.value,
            "summary": (
                f"Containment retry {retry_number}/{MAX_RETRIES}: "
                f"{phase} failed ({failure_message[:80]}), "
                f"trying new strategy"
            ),
        })

    async def _retries_exhausted(self, incident_id: str, resource: str):
        """
        All retries used up. Send email notification and pass to Investigation
        with 'partially_contained' status. Investigation always runs.
        """
        log.warning("Containment retries exhausted",
                    incident_id=incident_id,
                    max_retries=MAX_RETRIES)

        self._retry_counts.pop(incident_id, None)

        # Update incident status
        await update_incident(incident_id, {
            "status": IncidentStatus.INVESTIGATING.value,
        })

        # Email notification to human
        await queue.push("notification", {
            "type": "containment_retries_exhausted",
            "incident_id": incident_id,
            "severity": "P1",  # Always critical when we can't contain
            "channels": ["email"],  # Force email
            "resource": resource,
            "max_retries": MAX_RETRIES,
            "summary": (
                f"ALERT: Containment failed after {MAX_RETRIES} attempts for "
                f"incident {incident_id} on resource {resource}. "
                f"Manual intervention may be required. "
                f"Investigation is proceeding automatically."
            ),
            "requires_human_attention": True,
        })

        # Still pass to Investigation — it needs to run regardless
        await self._pass_to_investigation(
            incident_id,
            action_id=None,
            action_type=None,
            resource=resource,
            containment_status="partially_contained",
        )

    # ================================================================
    # HELPERS
    # ================================================================

    async def _pass_to_investigation(
        self,
        incident_id: str,
        action_id: Optional[str],
        action_type: Optional[str],
        resource: str,
        containment_status: str,
    ):
        """Push to investigation queue. Always called, regardless of containment outcome."""
        await update_incident(incident_id, {
            "status": IncidentStatus.INVESTIGATING.value,
        })

        await queue.push("investigation", {
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_type,
            "resource": resource,
            "containment_status": containment_status,
            # Let Investigation Agent know full context is available
            "use_context_agent": True,
        })

        log.info("Passed to Investigation Agent",
                 incident_id=incident_id,
                 containment_status=containment_status)

    async def _save_validation_result(
        self,
        action_id: str,
        incident_id: str,
        phase: str,
        success: bool,
        message: str,
    ):
        try:
            import aiosqlite
            async with aiosqlite.connect(config.sqlite_path) as db:
                await db.execute("""
                    INSERT INTO validation_attempts (action_id, incident_id, phase, success, message)
                    VALUES (?, ?, ?, ?, ?)
                """, (action_id, incident_id, phase, 1 if success else 0, message))
                await db.commit()
        except Exception as e:
            log.error("Failed to save validation result", error=str(e))

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_validations": self.validation_count,
            "phase2_failures": self.phase2_failures,
            "phase3_failures": self.phase3_failures,
            "active_retry_incidents": len(self._retry_counts),
            "retry_counts": dict(self._retry_counts),
        }


# Service instance
validation_service = ValidationService()