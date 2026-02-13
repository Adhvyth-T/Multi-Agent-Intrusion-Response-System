"""
Delete Pod Executor - Windows-compatible using Docker CLI.
WITH IVAM VALIDATION (Phase 2, Phase 3) AND FALLBACK STRATEGIES
"""

from typing import Dict, Any, Optional, List
import structlog

from config import config
from core.actions.base import BaseActionExecutor
from core.actions.registry import action_executor
from core.actions.models import ActionResult, ActionStatus

log = structlog.get_logger()


@action_executor("delete_pod")
class DeletePodExecutor(BaseActionExecutor):
    """Deletes a Docker container using Docker CLI."""
    
    action_name = "delete_pod"
    description = "Delete container/pod to stop malicious process"
    destructive = True
    requires_snapshot = True
    reversible = False
    
    @classmethod
    def get_required_params(cls):
        return []  # resource provides container name
    
    @classmethod
    def get_optional_params(cls):
        return ["grace_period", "force"]
    
    async def validate_params(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate delete_pod parameters."""
        grace_period = params.get("grace_period", 0)
        if not isinstance(grace_period, int) or grace_period < 0:
            return False, "grace_period must be non-negative integer"
        
        return True, None
    
    async def validate_preconditions(
        self, 
        resource: str, 
        params: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """Check if container exists."""
        container_name = self._extract_container_name(resource)
        
        if not self._container_exists(container_name):
            # List available containers for debugging
            success, stdout, _ = self._run_docker_command(
                ['ps', '-a', '--format', '{{.Names}}'],
                check=False
            )
            available = stdout.split('\n')[:5] if success else []
            
            return False, f"Container not found: {container_name}. Available: {available}"
        
        # Check if already stopped
        status = self._get_container_status(container_name)
        if status in ['exited', 'dead', 'removing']:
            return False, f"Container already in {status} state"
        
        return True, None
    
    async def execute(
        self,
        incident_id: str,
        resource: str,
        params: Dict[str, Any]
    ) -> ActionResult:
        """Execute container deletion."""
        container_name = self._extract_container_name(resource)
        
        log.info("Executing delete_pod",
                incident_id=incident_id,
                resource=resource,
                container_name=container_name)
        
        # DRY RUN MODE
        if config.DRY_RUN:
            log.info("DRY RUN: Would delete container", container=container_name)
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would delete container {container_name}",
                details={
                    "container_name": container_name,
                    "simulated": True
                }
            )
        
        try:
            # Delete container (force)
            force_flag = '-f' if params.get("force", True) else ''
            cmd = ['rm', container_name]
            if force_flag:
                cmd.insert(1, force_flag)
            
            success, stdout, stderr = self._run_docker_command(cmd, check=False)
            
            if success:
                log.info("Container deleted",
                        container_name=container_name)
                
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Container {container_name} deleted successfully",
                    details={"container_name": container_name}
                )
            else:
                log.error("Failed to delete container",
                         container=container_name,
                         stderr=stderr)
                
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Failed to delete: {stderr}",
                    error=stderr
                )
        
        except Exception as e:
            log.error("Unexpected error during delete_pod",
                     resource=resource,
                     error=str(e))
            
            return self._create_result(
                status=ActionStatus.FAILED,
                success=False,
                message=f"Unexpected error: {str(e)}",
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
        """Phase 1: Verify container is gone (immediate)."""
        if config.DRY_RUN:
            return True, "DRY RUN: Verification skipped"
        
        container_name = self._extract_container_name(resource)
        
        try:
            exists = self._container_exists(container_name)
            
            if not exists:
                return True, "Container successfully removed"
            
            # Still exists - check status
            status = self._get_container_status(container_name)
            if status in ['removing', 'dead']:
                return True, f"Container in {status} state (deletion in progress)"
            
            return False, f"Container still exists with status: {status}"
            
        except Exception as e:
            log.error("Error verifying deletion", resource=resource, error=str(e))
            return False, f"Verification error: {str(e)}"
    
    async def verify_sustained(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 2: Verify container stayed deleted (5 min wait).
        Check if container respawned with same name.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        # Wait 5 minutes
        import asyncio
        await asyncio.sleep(300)
        
        container_name = self._extract_container_name(resource)
        
        try:
            exists = self._container_exists(container_name)
            
            if not exists:
                return True, "Container stayed deleted (no respawn detected)"
            
            # Container reappeared!
            log.warning("Container respawned after deletion",
                       container=container_name)
            return False, f"Container respawned with name {container_name}"
            
        except Exception as e:
            return False, f"Sustained verification error: {str(e)}"
    
    async def verify_effective(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 3: For deleted containers, if Phase 1 & 2 passed,
        threat is definitely eliminated (container is gone).
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        # For delete action, if container is gone and stayed gone,
        # the threat is eliminated
        return True, "Threat eliminated (container deleted and stayed deleted)"
    
    # =========================================================================
    # FALLBACK STRATEGIES
    # =========================================================================
    
    def get_fallback_actions(self, action_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fallback if deletion fails:
        Level 2: Try kill then delete
        Level 3: Pause + network isolate
        Level 4: Alert for manual intervention
        """
        container_name = action_params.get("container_name")
        
        return [
            # Level 2: Kill first, then force delete
            {
                "action": "restart_container",
                "params": {
                    "container_name": container_name,
                    "timeout": 5
                }
            },
            # Level 3: If restart doesn't work, pause + isolate
            {
                "action": "pause_container",
                "params": {
                    "container_name": container_name
                }
            },
            # Level 4: Manual intervention needed
            {
                "action": "alert_manual",
                "params": {
                    "message": f"All automated containment failed for {container_name}",
                    "priority": "critical"
                }
            }
        ]