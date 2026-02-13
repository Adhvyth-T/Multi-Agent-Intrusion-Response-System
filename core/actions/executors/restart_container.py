"""
Restart Container Executor - Restart container to clear malicious processes.
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


@action_executor("restart_container")
class RestartContainerExecutor(BaseActionExecutor):
    """Restart container to clear malicious processes."""
    
    action_name = "restart_container"
    description = "Restart container to clear runtime malware (preserves data)"
    destructive = False
    requires_snapshot = False
    reversible = False
    
    @classmethod
    def get_optional_params(cls):
        return ["timeout"]
    
    async def validate_params(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        timeout = params.get("timeout", 10)
        if not isinstance(timeout, int) or timeout < 0:
            return False, "timeout must be non-negative integer"
        return True, None
    
    async def validate_preconditions(
        self, 
        resource: str, 
        params: Dict[str, Any]
    ) -> tuple[bool, Optional[str]]:
        """Check if container exists."""
        container_name = self._extract_container_name(resource)
        
        if not self._container_exists(container_name):
            return False, f"Container not found: {container_name}"
        
        return True, None
    
    async def execute(
        self,
        incident_id: str,
        resource: str,
        params: Dict[str, Any]
    ) -> ActionResult:
        """Restart container."""
        container_name = self._extract_container_name(resource)
        timeout = params.get("timeout", 10)
        
        log.info("Restarting container",
                container=container_name,
                timeout=timeout)
        
        if config.DRY_RUN:
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would restart {container_name}",
                details={"container_name": container_name}
            )
        
        try:
            # Restart with timeout
            cmd = ['restart', '-t', str(timeout), container_name]
            success, stdout, stderr = self._run_docker_command(cmd, check=False)
            
            if success:
                log.info("Container restarted", container=container_name)
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Container {container_name} restarted",
                    details={
                        "container_name": container_name,
                        "timeout": timeout
                    }
                )
            else:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message=f"Failed to restart: {stderr}",
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
        """Phase 1: Verify container restarted and is running (immediate)."""
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            import asyncio
            await asyncio.sleep(2)  # Wait for restart to complete
            
            status = self._get_container_status(container_name)
            
            if status == 'up':
                return True, "Container restarted and running"
            elif status == 'restarting':
                # Still restarting, give it more time
                await asyncio.sleep(3)
                status = self._get_container_status(container_name)
                if status == 'up':
                    return True, "Container restarted and running"
                return False, f"Container stuck restarting (status: {status})"
            else:
                return False, f"Container not running after restart (status: {status})"
        
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    async def verify_sustained(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 2: Verify container stayed healthy (5 min wait).
        Check if container crashed or restarted again.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        # Get current restart count as baseline
        try:
            success, inspect_json, _ = self._run_docker_command(
                ['inspect', container_name, '--format', '{{.RestartCount}}'],
                check=False
            )
            initial_restart_count = int(inspect_json) if success and inspect_json.isdigit() else 0
        except:
            initial_restart_count = 0
        
        # Wait 5 minutes
        import asyncio
        await asyncio.sleep(300)
        
        try:
            # Check if container is still running
            status = self._get_container_status(container_name)
            
            if status != 'up':
                log.warning("Container crashed after restart",
                           container=container_name,
                           status=status)
                return False, f"Container crashed (status: {status})"
            
            # Check if container restarted again (indicates persistent issue)
            success, inspect_json, _ = self._run_docker_command(
                ['inspect', container_name, '--format', '{{.RestartCount}}'],
                check=False
            )
            current_restart_count = int(inspect_json) if success and inspect_json.isdigit() else 0
            
            if current_restart_count > initial_restart_count:
                log.warning("Container restarted again (crash loop?)",
                           container=container_name,
                           restart_count=current_restart_count)
                return False, f"Container restarted {current_restart_count - initial_restart_count} more time(s)"
            
            return True, "Container stayed healthy (no crashes)"
            
        except Exception as e:
            return False, f"Sustained verification error: {str(e)}"
    
    async def verify_effective(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 3: Verify malicious behavior cleared.
        For runtime malware (like cryptominers), check CPU usage normalized.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            # Get container stats (CPU usage)
            success, stats_json, _ = self._run_docker_command(
                ['stats', container_name, '--no-stream', '--format', '{{.CPUPerc}}'],
                check=False
            )
            
            if success and stats_json:
                # Parse CPU percentage (e.g., "45.67%" -> 45.67)
                cpu_str = stats_json.strip().rstrip('%')
                try:
                    cpu_percent = float(cpu_str)
                    
                    # Normal CPU should be < 50% after restart (if it was cryptominer)
                    if cpu_percent < 50:
                        return True, f"CPU usage normalized ({cpu_percent:.1f}%) - malware likely cleared"
                    
                    log.warning("High CPU usage after restart",
                               container=container_name,
                               cpu_percent=cpu_percent)
                    return False, f"High CPU usage persists ({cpu_percent:.1f}%) - malware may remain"
                
                except ValueError:
                    # Can't parse CPU - assume okay if container is running
                    pass
            
            # If we can't check CPU, just verify container is running
            status = self._get_container_status(container_name)
            if status == 'up':
                return True, "Container running (CPU check unavailable)"
            
            return False, f"Container not running (status: {status})"
            
        except Exception as e:
            return False, f"Effectiveness verification error: {str(e)}"
    
    # =========================================================================
    # FALLBACK STRATEGIES
    # =========================================================================
    
    def get_fallback_actions(self, action_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fallback if restart fails:
        Level 2: Pause container (freeze it)
        Level 3: Delete container (malware persists)
        """
        container_name = action_params.get("container_name")
        
        return [
            # Level 2: If restart doesn't clear malware, pause to freeze it
            {
                "action": "pause_container",
                "params": {
                    "container_name": container_name
                }
            },
            # Level 3: If pause doesn't work, delete
            {
                "action": "delete_pod",
                "params": {
                    "container_name": container_name,
                    "force": True
                }
            }
        ]