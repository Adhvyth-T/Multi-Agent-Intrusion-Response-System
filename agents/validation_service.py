"""
Validation Service - Runs IVAM Phase 2 & 3 verification in background.
Subscribes to "validation" queue and runs sustained/effective validation.
"""

import asyncio
import json
from datetime import datetime
from typing import Dict, Any
import structlog

from config import config
from core import queue
from core.actions import ActionRegistry, ActionResult

log = structlog.get_logger()


class ValidationService:
    """
    Background service for IVAM Phase 2 & 3 validation.
    
    Workflow:
    1. Subscribe to "validation" queue
    2. Get executor for action type
    3. Run Phase 2 (sustained) after 5 minutes
    4. Run Phase 3 (effective) after Phase 2
    5. If any phase fails → Trigger fallback
    6. Update database with results
    7. Send notifications
    """
    
    def __init__(self):
        self.running = False
        self.validation_count = 0
        self.phase2_failures = 0
        self.phase3_failures = 0
    
    async def start(self):
        """Start the validation service."""
        self.running = True
        
        log.info("Validation Service started",
                queue="validation")
        
        await self._validation_loop()
    
    async def stop(self):
        """Stop the validation service."""
        self.running = False
        log.info("Validation Service stopped",
                total_validations=self.validation_count,
                phase2_failures=self.phase2_failures,
                phase3_failures=self.phase3_failures)
    
    async def _validation_loop(self):
        """Main loop processing validation queue."""
        while self.running:
            try:
                validation_request = await queue.pop("validation", timeout=5)
                
                if validation_request:
                    # Run validation in background task (don't block queue)
                    asyncio.create_task(
                        self._process_validation(validation_request)
                    )
            except Exception as e:
                log.error("Error in validation loop", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_validation(self, request: Dict[str, Any]):
        """Process Phase 2 & 3 validation for an action."""
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
        
        # Get executor
        executor_class = ActionRegistry.get(action_type)
        if not executor_class:
            log.error("Unknown action type for validation",
                     action_type=action_type)
            return
        
        try:
            executor = executor_class()
        except Exception as e:
            log.error("Failed to create executor for validation",
                     action_type=action_type,
                     error=str(e))
            return
        
        # Reconstruct ActionResult
        result = ActionResult(**result_dict)
        
        # Phase 2: Sustained validation (5 minutes)
        try:
            phase2_success, phase2_msg = await executor.verify_sustained(resource, result)
            
            log.info("Phase 2 validation complete",
                    incident_id=incident_id,
                    action_id=action_id,
                    success=phase2_success,
                    message=phase2_msg)
            
            # Save Phase 2 result
            await self._save_validation_result(
                action_id, incident_id, "sustained",
                phase2_success, phase2_msg
            )
            
            # Send notification
            await queue.push("notification", {
                "type": "validation_phase2",
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "phase": "sustained",
                "success": phase2_success,
                "message": phase2_msg
            })
            
            if not phase2_success:
                self.phase2_failures += 1
                log.warning("Phase 2 validation failed - triggering fallback",
                           incident_id=incident_id,
                           action_id=action_id,
                           reason=phase2_msg)
                
                # Trigger fallback
                await self._trigger_fallback(
                    incident_id, action_id, action_type, resource,
                    result, "phase2_failed", phase2_msg
                )
                return  # Don't proceed to Phase 3
            
        except Exception as e:
            log.error("Phase 2 validation error",
                     incident_id=incident_id,
                     action_id=action_id,
                     error=str(e))
            self.phase2_failures += 1
            return
        
        # Phase 3: Effective validation
        try:
            phase3_success, phase3_msg = await executor.verify_effective(resource, result)
            
            log.info("Phase 3 validation complete",
                    incident_id=incident_id,
                    action_id=action_id,
                    success=phase3_success,
                    message=phase3_msg)
            
            # Save Phase 3 result
            await self._save_validation_result(
                action_id, incident_id, "effective",
                phase3_success, phase3_msg
            )
            
            # Send notification
            await queue.push("notification", {
                "type": "validation_phase3",
                "incident_id": incident_id,
                "action_id": action_id,
                "action_type": action_type,
                "phase": "effective",
                "success": phase3_success,
                "message": phase3_msg
            })
            
            if not phase3_success:
                self.phase3_failures += 1
                log.warning("Phase 3 validation failed",
                           incident_id=incident_id,
                           action_id=action_id,
                           reason=phase3_msg)
                
                # Trigger early investigation
                await queue.push("investigation", {
                    "incident_id": incident_id,
                    "priority": "URGENT",
                    "reason": "Containment ineffective",
                    "validation_failure": {
                        "phase": "effective",
                        "message": phase3_msg
                    }
                })
            else:
                log.info("All 3 validation phases passed",
                        incident_id=incident_id,
                        action_id=action_id)
                
                # Success - send to investigation normally
                await queue.push("investigation", {
                    "incident_id": incident_id,
                    "action_id": action_id,
                    "action_type": action_type,
                    "validation_complete": True
                })
            
        except Exception as e:
            log.error("Phase 3 validation error",
                     incident_id=incident_id,
                     action_id=action_id,
                     error=str(e))
            self.phase3_failures += 1
    
    async def _save_validation_result(
        self,
        action_id: str,
        incident_id: str,
        phase: str,
        success: bool,
        message: str
    ):
        """Save validation result to database."""
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
    
    async def _trigger_fallback(
        self,
        incident_id: str,
        action_id: str,
        action_type: str,
        resource: str,
        original_result: ActionResult,
        reason: str,
        details: str
    ):
        """Trigger fallback strategy when validation fails."""
        log.info("Triggering fallback strategy",
                incident_id=incident_id,
                action_id=action_id,
                reason=reason)
        
        # Get executor to fetch fallback actions
        executor_class = ActionRegistry.get(action_type)
        if not executor_class:
            log.error("Cannot get fallback - unknown action type", action_type=action_type)
            return
        
        try:
            executor = executor_class()
            fallback_actions = executor.get_fallback_actions(original_result.details)
            
            if not fallback_actions:
                log.warning("No fallback actions defined for action type",
                           action_type=action_type)
                
                # Alert for manual intervention
                await queue.push("notification", {
                    "type": "validation_failed_no_fallback",
                    "incident_id": incident_id,
                    "action_id": action_id,
                    "severity": "CRITICAL",
                    "message": f"Validation failed and no fallback available: {details}",
                    "requires_manual_intervention": True
                })
                return
            
            # Execute first fallback action
            first_fallback = fallback_actions[0]
            log.info("Executing fallback action",
                    incident_id=incident_id,
                    fallback_action=first_fallback["action"],
                    reason=first_fallback.get("reason"))
            
            # Queue fallback action for execution
            await queue.push("containment", {
                "incident_id": incident_id,
                "action": {
                    "action_type": first_fallback["action"],
                    "params": first_fallback["params"],
                    "resource": resource,
                    "is_fallback": True,
                    "original_action_id": action_id,
                    "fallback_reason": reason
                }
            })
            
        except Exception as e:
            log.error("Failed to trigger fallback", error=str(e))
    
    def get_stats(self) -> Dict[str, Any]:
        """Get validation service statistics."""
        return {
            "total_validations": self.validation_count,
            "phase2_failures": self.phase2_failures,
            "phase3_failures": self.phase3_failures,
            "phase2_success_rate": (
                1 - (self.phase2_failures / self.validation_count)
                if self.validation_count > 0 else 0
            ),
            "phase3_success_rate": (
                1 - (self.phase3_failures / self.validation_count)
                if self.validation_count > 0 else 0
            )
        }


# Service instance
validation_service = ValidationService()