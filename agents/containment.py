"""
Containment Agent - Week 3, Days 1-3
Executes containment actions using registered action executors.
"""

import asyncio
import uuid
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
    8. Push to validation queue (for Phase 2+3)
    9. Send notification
    """
    
    def __init__(self):
        self.running = False
        self.execution_count = 0
        self.success_count = 0
        self.failure_count = 0
    
    async def start(self):
        """Start the containment agent."""
        self.running = True
        
        # Log available executors
        available_actions = ActionRegistry.list_available()
        log.info("Containment Agent started",
                available_actions=available_actions,
                dry_run=config.DRY_RUN)
        
        if config.DRY_RUN:
            log.warning("🧪 DRY RUN MODE ENABLED - No actual actions will be executed")
        
        await self._containment_loop()
    
    async def stop(self):
        """Stop the containment agent."""
        self.running = False
        log.info("Containment Agent stopped",
                total_actions=self.execution_count,
                successful=self.success_count,
                failed=self.failure_count)
    
    async def _containment_loop(self):
        """Main loop processing containment queue."""
        while self.running:
            try:
                action_request = await queue.pop("containment", timeout=5)
                
                if action_request:
                    await self._process_action_request(action_request)
            except Exception as e:
                log.error("Error in containment loop", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_action_request(self, request: Dict[str, Any]):
        """Process a single action request."""
        incident_id = request.get("incident_id")
        action_data = request.get("action", request)  # Support both formats
        action_type = action_data.get("action_type") or action_data.get("action")
        action_id = action_data.get("id") or action_data.get("action_id")
        
        log.info("Processing containment action",
                incident_id=incident_id,
                action_id=action_id,
                action_type=action_type)
        
        self.execution_count += 1
        
        # Get executor from registry
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
        
        # Create executor instance
        try:
            executor = executor_class()
        except Exception as e:
            log.error("Failed to create executor", action_type=action_type, error=str(e))
            await self._report_failure(
                incident_id, action_id, action_type,
                f"Failed to initialize executor: {str(e)}"
            )
            return
        
        # Execute action with full workflow
        result = await self._execute_action_workflow(
            executor, incident_id, action_data
        )
        
        # Update statistics
        if result.success:
            self.success_count += 1
        else:
            self.failure_count += 1
        
        # Save action result
        await self._save_action_result(action_id, result)
        
        # Update incident status
        if result.success:
            await update_incident(incident_id, {"status": "containment"})
        
        # Send notification
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
        
        # Push to validation queue (IVAM Phase 2+3)
        if result.success and result.verified_immediate:
            await queue.push("validation", {
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "result": result.to_dict(),
                "resource": action_data.get("resource", "unknown")
            })
    
    async def _execute_action_workflow(
        self,
        executor,
        incident_id: str,
        action_data: Dict[str, Any]
    ) -> ActionResult:
        """
        Execute complete action workflow with validation, snapshot, and verification.
        
        Workflow:
        1. Extract parameters
        2. Validate parameters
        3. Validate preconditions
        4. Capture snapshot (if needed)
        5. Execute action
        6. Verify immediate (IVAM Phase 1)
        7. Return result
        """
        action_type = action_data.get("action_type") or action_data.get("action")
        resource = action_data.get("resource", "unknown")
        namespace = action_data.get("namespace", "docker")
        params = action_data.get("params", {})
        
        # Add resource to params if not present
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
                log.warning("Parameter validation failed",
                           action_type=action_type,
                           error=error_msg)
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
                snapshot = await executor.capture_snapshot(
                    incident_id, resource, namespace
                )
                if snapshot:
                    log.info("Forensic snapshot captured",
                            snapshot_id=snapshot.snapshot_id,
                            size_bytes=snapshot.size_bytes)
                    
                    # TODO: Save snapshot to database/storage
                    # await save_snapshot(snapshot.to_dict())
            except Exception as e:
                log.error("Failed to capture snapshot", error=str(e))
                # Continue anyway - don't fail action due to snapshot failure
        
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
    
    async def _save_action_result(self, action_id: str, result: ActionResult):
        """Save action result to database."""
        try:
            await update_action(action_id, {
                "status": result.status.value,
                "result": result.message,
                "details": result.details,
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
        """Report action failure."""
        self.failure_count += 1
        
        # Update action record
        try:
            await update_action(action_id, {
                "status": ActionStatus.FAILED.value,
                "result": error_message,
                "details": details or {}
            })
        except Exception as e:
            log.error("Failed to update action", error=str(e))
        
        # Send notification
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
        """Get containment agent statistics."""
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
