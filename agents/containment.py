"""
Containment Agent
Executes containment actions using registered action executors.
Updates context after every execution so Decision Agent has full picture on retry.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any, List, Optional
import structlog

from config import config
from core import queue, update_incident, save_action, update_action, IncidentStatus
from core.actions import ActionRegistry, ActionResult, ActionStatus, ForensicSnapshot

log = structlog.get_logger()


class ContainmentAgent:
    """
    Main containment agent that executes actions.

    Workflow:
    1. Pop action request from "containment" queue
    2. Get appropriate executor from ActionRegistry
    3. Validate parameters and preconditions
    4. Capture forensic snapshot (if destructive)
    5. Execute action
    6. Verify execution (IVAM Phase 1)
    7. Save results
    8. Update context (so Decision Agent sees outcome on retry)
    9. Push to validation queue (for Phase 2+3)
    10. Send notification
    """

    def __init__(self):
        self.running = False
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0

    async def start(self):
        self.running = True
        available_actions = ActionRegistry.list_available()
        log.info("Containment Agent started",
                 available_actions=available_actions,
                 dry_run=config.DRY_RUN)
        if config.DRY_RUN:
            log.warning("DRY RUN MODE ENABLED - No actual actions will be executed")
        await self._containment_loop()

    async def stop(self):
        self.running = False
        log.info("Containment Agent stopped",
                 total_actions=self.execution_count,
                 successful=self.success_count,
                 failed=self.failure_count)

    async def _containment_loop(self):
        while self.running:
            try:
                action_request = await queue.pop("containment", timeout=5)
                if action_request:
                    await self._process_action_request(action_request)
            except Exception as e:
                log.error("Error in containment loop", error=str(e))
                await asyncio.sleep(1)

    async def _process_action_request(self, request: Dict[str, Any]):
        incident_id = request.get("incident_id")
        action_data = request.get("action", request)
        action_type = action_data.get("action_type") or action_data.get("action")
        action_id = action_data.get("id") or action_data.get("action_id")

        log.info("Processing containment action",
                 incident_id=incident_id,
                 action_id=action_id,
                 action_type=action_type)

        self.execution_count += 1

        executor_class = ActionRegistry.get(action_type)
        if not executor_class:
            log.error("Unknown action type",
                      action_type=action_type,
                      available=ActionRegistry.list_available())
            await self._report_failure(
                incident_id, action_id, action_type,
                f"Unknown action type: {action_type}",
                {"available_actions": ActionRegistry.list_available()}
            )
            return

        try:
            executor = executor_class()
        except Exception as e:
            log.error("Failed to create executor", action_type=action_type, error=str(e))
            await self._report_failure(
                incident_id, action_id, action_type,
                f"Failed to initialize executor: {str(e)}"
            )
            return

        result = await self._execute_action_workflow(executor, incident_id, action_data)

        if result.success:
            self.success_count += 1
        else:
            self.failure_count += 1

        await self._save_action_result(action_id, result)

        # Always update context with outcome — this is what Decision Agent reads on retry
        # "Container not found" messages here are exactly what LLM needs to detect
        # that the container is already gone and containment succeeded
        await self._update_context_after_execution(incident_id, action_type, result, action_data)

        if result.success:
            await update_incident(incident_id, {"status": "containment"})

        await queue.push("notification", {
            "type": "action_executed",
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_type,
            "severity": request.get("severity", "P3"),
            "status": result.status.value,
            "result": result.message,
            "success": result.success,
            "duration_seconds": result.duration_seconds
        })

        # Always push to validation — on success Phase 2+3 run normally.
        # On failure, ValidationService detects execution_failed=True and immediately
        # calls _handle_validation_failure → Decision Agent retry loop with full context.
        # "partial" means the action ran but immediate verify had a timing issue —
        # Phase 2 is the real judge, so that also goes through normally.
        await queue.push("validation", {
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_type,
            "result": result.to_dict(),
            "resource": action_data.get("resource", "unknown"),
            "execution_failed": not result.success,
            "failure_message": result.message if not result.success else None,
        })

    async def _execute_action_workflow(
        self,
        executor,
        incident_id: str,
        action_data: Dict[str, Any]
    ) -> ActionResult:
        action_type = action_data.get("action_type") or action_data.get("action")
        resource = action_data.get("resource", "unknown")
        namespace = action_data.get("namespace", "docker")
        params = action_data.get("params", {})

        if "container_id" not in params and "container_name" not in params:
            params["container_name"] = resource
            params["container_id"] = resource

        log.debug("Executing action workflow",
                  action_type=action_type,
                  resource=resource,
                  params=params)

        # 1. Validate parameters
        try:
            valid, error_msg = await executor.validate_params(params)
            if not valid:
                log.warning("Parameter validation failed", action_type=action_type, error=error_msg)
                return ActionResult(
                    action_type=action_type,
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Invalid parameters: {error_msg}",
                    error=error_msg
                )
        except Exception as e:
            log.error("Parameter validation error", error=str(e))
            return ActionResult(
                action_type=action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Validation error: {str(e)}",
                error=str(e)
            )

        # 2. Validate preconditions
        try:
            can_execute, error_msg = await executor.validate_preconditions(resource, params)
            if not can_execute:
                log.warning("Precondition check failed",
                            action_type=action_type,
                            resource=resource,
                            error=error_msg)
                return ActionResult(
                    action_type=action_type,
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Preconditions not met: {error_msg}",
                    error=error_msg
                )
        except Exception as e:
            log.error("Precondition check error", error=str(e))
            return ActionResult(
                action_type=action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Precondition error: {str(e)}",
                error=str(e)
            )

        # 3. Capture forensic snapshot (if destructive)
        snapshot = None
        if executor.requires_snapshot and config.ENABLE_SNAPSHOTS:
            try:
                snapshot = await executor.capture_snapshot(incident_id, resource, namespace)
                if snapshot:
                    log.info("Forensic snapshot captured",
                             snapshot_id=snapshot.snapshot_id,
                             size_bytes=snapshot.size_bytes)
            except Exception as e:
                log.error("Failed to capture snapshot", error=str(e))
                # Don't fail the action for a snapshot failure

        # 4. Execute action
        try:
            result = await executor.execute(incident_id, resource, params)
            if snapshot:
                result.snapshot_id = snapshot.snapshot_id
            log.info("Action executed",
                     action_type=action_type,
                     resource=resource,
                     status=result.status.value,
                     success=result.success)
        except Exception as e:
            log.error("Action execution failed",
                      action_type=action_type,
                      resource=resource,
                      error=str(e),
                      exc_info=True)
            return ActionResult(
                action_type=action_type,
                status=ActionStatus.FAILED,
                success=False,
                message=f"Execution failed: {str(e)}",
                error=str(e)
            )

        # 5. Verify immediate (IVAM Phase 1)
        if result.success:
            try:
                verified, verify_msg = await executor.verify_immediate(resource, result)
                result.verified_immediate = verified
                result.verification_details = {"phase_1": verify_msg}
                if not verified:
                    log.warning("Immediate verification failed",
                                action_type=action_type,
                                resource=resource,
                                message=verify_msg)
                    result.status = ActionStatus.PARTIAL
                else:
                    log.info("Immediate verification passed",
                             action_type=action_type,
                             resource=resource)
            except Exception as e:
                log.error("Verification error", error=str(e))
                result.verification_details = {"phase_1": f"Verification error: {str(e)}"}

        return result

    async def _update_context_after_execution(
        self,
        incident_id: str,
        action_type: str,
        result: ActionResult,
        action_data: Dict[str, Any],
    ):
        """
        Update context cache with this action's outcome.

        Critical for the retry loop: Decision Agent reads this on retry to understand
        what happened. In particular, messages like "Container not found" on a
        delete_pod or network_isolate action tell the LLM the container is already
        gone — meaning containment already succeeded.

        Called unconditionally after every execution, success or failure.
        """
        try:
            from agents.context import context_agent

            # Read existing containment actions from cache to build running list.
            # phase_updates["containment"] is a list of dicts (update_context appends).
            # Flatten actions_taken from all previous entries to get the full history.
            current = context_agent._context_cache.get(incident_id, {})
            containment_history = (
                current
                .get("phase_updates", {})
                .get("containment", [])  # list, not dict
            )
            prev_actions = []
            for entry in containment_history:
                if isinstance(entry, dict):
                    prev_actions.extend(entry.get("actions_taken", []))

            actions_taken = prev_actions + [{
                "action_type": action_type,
                "success": result.success,
                "status": result.status.value,
                "message": result.message,
                "error": result.error,
                "verified_immediate": result.verified_immediate,
                "resource": action_data.get("resource"),
                "executed_at": datetime.utcnow().isoformat(),
            }]

            context_agent.update_context(incident_id, "containment", {
                "last_action_type": action_type,
                "last_action_success": result.success,
                "last_action_status": result.status.value,
                "last_action_message": result.message,
                "last_action_error": result.error,
                "resource": action_data.get("resource"),
                "actions_taken": actions_taken,
                "executed_at": datetime.utcnow().isoformat(),
            })

            log.debug("Context updated after execution",
                      incident_id=incident_id,
                      action_type=action_type,
                      success=result.success,
                      message=result.message)

        except Exception as e:
            # Never let a context update crash the containment pipeline
            log.error("Failed to update context after execution",
                      incident_id=incident_id,
                      action_type=action_type,
                      error=str(e))

    async def _save_action_result(self, action_id: str, result: ActionResult):
        """Save action result to database."""
        try:
            await update_action(action_id, {
                "status": result.status.value,
                "result": result.message,
                # FIX: was passing {} (a dict) when details is falsy — SQLite can't bind dicts
                "details": json.dumps(result.details) if result.details else None,
                "verified": result.verified_immediate,
                "executed_at": result.completed_at.isoformat() if result.completed_at else None,
                "duration_seconds": result.duration_seconds
            })
        except Exception as e:
            log.error("Failed to save action result", action_id=action_id, error=str(e))

    async def _report_failure(
        self,
        incident_id: str,
        action_id: str,
        action_type: str,
        error_message: str,
        details: Optional[Dict] = None
    ):
        self.failure_count += 1
        try:
            await update_action(action_id, {
                "status": ActionStatus.FAILED.value,
                "result": error_message,
                # FIX: same dict binding fix here
                "details": json.dumps(details) if details else None,
            })
        except Exception as e:
            log.error("Failed to update action", error=str(e))

        await queue.push("notification", {
            "type": "action_failed",
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_type,
            "severity": "P2",
            "error": error_message,
            "summary": f"Action {action_type} failed: {error_message}"
        })

    def get_stats(self) -> Dict[str, Any]:
        return {
            "total_executions": self.execution_count,
            "successful": self.success_count,
            "failed": self.failure_count,
            "success_rate": (
                self.success_count / self.execution_count
                if self.execution_count > 0 else 0
            ),
            "available_actions": ActionRegistry.list_available(),
            "dry_run_mode": config.DRY_RUN
        }


# Agent instance
containment_agent = ContainmentAgent()