"""
Pause Container Executor - Freeze container execution.
Windows-compatible using Docker CLI.
WITH IVAM VALIDATION (Phase 2, Phase 3) AND FALLBACK STRATEGIES
"""

from typing import Dict, Any, Optional, List
import structlog

from config import config
from core.actions.base import BaseActionExecutor
from core.actions.registry import action_executor
from core.actions.models import ActionResult, ActionStatus

log = structlog.get_logger()


@action_executor("pause_container")
class PauseContainerExecutor(BaseActionExecutor):
    """Pause container execution without killing it."""
    
    action_name = "pause_container"
    description = "Pause container execution (less destructive than delete)"
    destructive = False
    requires_snapshot = False
    reversible = True
    
    async def validate_params(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        return True, None
    
    async def validate_preconditions(
        self, 
        resource: str, 
        params: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """Check if container exists and is running."""
        container_name = self._extract_container_name(resource)
        
        if not self._container_exists(container_name):
            return False, f"Container not found: {container_name}"
        
        status = self._get_container_status(container_name)
        if status == 'paused':
            return False, "Container already paused"
        if status != 'up':
            return False, f"Container not running (status: {status})"
        
        return True, None
    
    async def execute(
        self,
        incident_id: str,
        resource: str,
        params: Dict[str, Any]
    ) -> ActionResult:
        """Pause container."""
        container_name = self._extract_container_name(resource)
        
        log.info("Pausing container", container=container_name)
        
        if config.DRY_RUN:
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would pause {container_name}",
                details={"container_name": container_name}
            )
        
        try:
            success, stdout, stderr = self._run_docker_command(
                ['pause', container_name],
                check=False
            )
            
            if success:
                log.info("Container paused", container=container_name)
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Container {container_name} paused",
                    details={"container_name": container_name}
                )
            else:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Failed to pause: {stderr}",
                    error=stderr
                )
        
        except Exception as e:
            return self._create_result(
                status=ActionStatus.FAILED,
                success=False,
                message=f"Error: {str(e)}",
                error=str(e)
            )
    
    # =========================================================================
    # IVAM VALIDATION - 3 PHASES
    # =========================================================================
    
    async def verify_immediate(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """Phase 1: Verify container is paused (immediate)."""
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            status = self._get_container_status(container_name)
            
            if status == 'paused' or 'paused' in status.lower():
                return True, "Container paused successfully"
            
            return False, f"Container not paused (status: {status})"
        
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    async def verify_sustained(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 2: Verify container stayed paused (5 min wait).
        Check if something unpaused it.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        # Wait 5 minutes
        import asyncio
        await asyncio.sleep(300)
        
        container_name = self._extract_container_name(resource)
        
        try:
            status = self._get_container_status(container_name)
            
            if status == 'paused' or 'paused' in status.lower():
                return True, "Container stayed paused"
            
            # Container was unpaused!
            log.warning("Container was unpaused externally",
                       container=container_name,
                       status=status)
            return False, f"Container unpaused (status: {status})"
            
        except Exception as e:
            return False, f"Sustained verification error: {str(e)}"
    
    async def verify_effective(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 3: Verify threat behavior stopped.
        A paused container cannot execute code, so if it's paused, threat is frozen.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            # Verify container is still paused
            status = self._get_container_status(container_name)
            
            if status == 'paused' or 'paused' in status.lower():
                # Paused = all processes frozen = threat neutralized
                return True, "Container paused - all processes frozen, threat neutralized"
            
            # Container is not paused anymore
            log.warning("Container no longer paused during effectiveness check",
                       container=container_name,
                       status=status)
            return False, f"Container resumed execution (status: {status})"
            
        except Exception as e:
            return False, f"Effectiveness verification error: {str(e)}"
    
    # =========================================================================
    # FALLBACK STRATEGIES
    # =========================================================================
    
    def get_fallback_actions(self, action_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fallback if pause fails:
        Level 2: Restart container (clear malware in memory)
        Level 3: Delete container (nuclear option)
        """
        container_name = action_params.get("container_name")
        
        return [
            # Level 2: If pause doesn't work, try restart to clear malware
            {
                "action": "restart_container",
                "params": {
                    "container_name": container_name,
                    "timeout": 10
                }
            },
            # Level 3: If restart doesn't work, delete
            {
                "action": "delete_pod",
                "params": {
                    "container_name": container_name,
                    "force": True
                }
            }
        ]
    
    # =========================================================================
    # ROLLBACK (Unpause)
    # =========================================================================
    
    async def rollback(
        self,
        resource: str,
        params: Dict[str, Any],
        original_result: ActionResult
    ) -> ActionResult:
        """Unpause container."""
        container_name = self._extract_container_name(resource)
        
        log.info("Unpausing container (rollback)", container=container_name)
        
        if config.DRY_RUN:
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would unpause {container_name}"
            )
        
        try:
            success, _, stderr = self._run_docker_command(
                ['unpause', container_name],
                check=False
            )
            
            if success:
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Container {container_name} unpaused (rollback successful)",
                    details={"container_name": container_name}
                )
            else:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Failed to unpause: {stderr}",
                    error=stderr
                )
        
        except Exception as e:
            return self._create_result(
                status=ActionStatus.FAILED,
                success=False,
                message=f"Rollback error: {str(e)}",
                error=str(e)
            )