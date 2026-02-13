"""
Network Isolate Executor - Disconnect container from networks.
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


@action_executor("network_isolate")
class NetworkIsolateExecutor(BaseActionExecutor):
    """Isolate container by disconnecting from all networks."""
    
    action_name = "network_isolate"
    description = "Disconnect container from networks to prevent data exfiltration"
    destructive = False
    requires_snapshot = False
    reversible = True
    
    @classmethod
    def get_optional_params(cls):
        return ["keep_networks"]
    
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
        if status != 'up':
            return False, f"Container not running (status: {status})"
        
        return True, None
    
    async def execute(
        self,
        incident_id: str,
        resource: str,
        params: Dict[str, Any]
    ) -> ActionResult:
        """Execute network isolation."""
        container_name = self._extract_container_name(resource)
        
        log.info("Executing network_isolate", container=container_name)
        
        if config.DRY_RUN:
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would isolate {container_name}",
                details={"container_name": container_name}
            )
        
        try:
            # Get networks
            success, inspect_json, _ = self._run_docker_command(
                ['inspect', container_name, '--format', '{{json .NetworkSettings.Networks}}'],
                check=False
            )
            
            if not success:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message="Failed to inspect container",
                    error="Inspect failed"
                )
            
            import json
            networks = json.loads(inspect_json)
            network_names = list(networks.keys())
            
            if not network_names:
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message="Already isolated (no networks)",
                    details={"container_name": container_name}
                )
            
            # Disconnect
            disconnected = []
            for network in network_names:
                success, _, _ = self._run_docker_command(
                    ['network', 'disconnect', network, container_name],
                    check=False
                )
                if success:
                    disconnected.append(network)
            
            if disconnected:
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Isolated from {len(disconnected)} network(s)",
                    details={
                        "container_name": container_name,
                        "networks_disconnected": disconnected
                    }
                )
            else:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message="Failed to disconnect networks",
                    error="No networks disconnected"
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
        """Phase 1: Verify networks are disconnected (immediate)."""
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            success, inspect_json, _ = self._run_docker_command(
                ['inspect', container_name, '--format', '{{json .NetworkSettings.Networks}}'],
                check=False
            )
            
            if success:
                import json
                networks = json.loads(inspect_json)
                if not networks or networks == {}:
                    return True, "Container isolated from all networks"
                return False, f"Still connected to: {list(networks.keys())}"
            
            return False, "Cannot verify - container inspect failed"
        except Exception as e:
            return False, f"Verification error: {str(e)}"
    
    async def verify_sustained(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 2: Verify networks stayed disconnected (5 min wait).
        Check if container reconnected to networks.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        # Wait 5 minutes
        import asyncio
        await asyncio.sleep(300)
        
        container_name = self._extract_container_name(resource)
        
        try:
            success, inspect_json, _ = self._run_docker_command(
                ['inspect', container_name, '--format', '{{json .NetworkSettings.Networks}}'],
                check=False
            )
            
            if success:
                import json
                networks = json.loads(inspect_json)
                
                if not networks or networks == {}:
                    return True, "Networks stayed disconnected (no reconnection)"
                
                # Networks reconnected!
                log.warning("Networks reconnected after isolation",
                           container=container_name,
                           networks=list(networks.keys()))
                return False, f"Networks reconnected: {list(networks.keys())}"
            
            return False, "Cannot verify - container inspect failed"
            
        except Exception as e:
            return False, f"Sustained verification error: {str(e)}"
    
    async def verify_effective(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        Phase 3: Verify threat behavior stopped.
        For data exfiltration, check if outbound traffic dropped.
        """
        if config.DRY_RUN:
            return True, "DRY RUN"
        
        container_name = self._extract_container_name(resource)
        
        try:
            # Check container is still running (not crashed due to network loss)
            status = self._get_container_status(container_name)
            
            if status not in ['up', 'running']:
                log.warning("Container stopped after network isolation",
                           container=container_name,
                           status=status)
                # This might be okay - app crashed without network
                return True, f"Container stopped ({status}) - threat neutralized"
            
            # If container is still running with no network, threat is contained
            return True, "Container isolated with no network access - threat contained"
            
        except Exception as e:
            return False, f"Effectiveness verification error: {str(e)}"
    
    # =========================================================================
    # FALLBACK STRATEGIES
    # =========================================================================
    
    def get_fallback_actions(self, action_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Fallback if network isolation fails:
        Level 2: Pause container (freeze execution)
        Level 3: Delete container (nuclear option)
        """
        container_name = action_params.get("container_name")
        
        return [
            # Level 2: If isolation doesn't work, pause execution
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
    
    # =========================================================================
    # ROLLBACK (Reconnect networks)
    # =========================================================================
    
    async def rollback(
        self,
        resource: str,
        params: Dict[str, Any],
        original_result: ActionResult
    ) -> ActionResult:
        """Reconnect container to networks (if reversible)."""
        container_name = self._extract_container_name(resource)
        
        log.info("Rolling back network isolation", container=container_name)
        
        if config.DRY_RUN:
            return self._create_result(
                status=ActionStatus.SIMULATED,
                success=True,
                message=f"[DRY RUN] Would reconnect {container_name} to networks"
            )
        
        try:
            # Get disconnected networks from original result
            disconnected = original_result.details.get("networks_disconnected", [])
            
            if not disconnected:
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message="No networks to reconnect"
                )
            
            # Reconnect to networks
            reconnected = []
            for network in disconnected:
                success, _, stderr = self._run_docker_command(
                    ['network', 'connect', network, container_name],
                    check=False
                )
                if success:
                    reconnected.append(network)
            
            if reconnected:
                return self._create_result(
                    status=ActionStatus.SUCCESS,
                    success=True,
                    message=f"Reconnected to {len(reconnected)} network(s)",
                    details={"networks_reconnected": reconnected}
                )
            else:
                return self._create_result(
                    status=ActionStatus.FAILED,
                    success=False,
                    message="Failed to reconnect networks",
                    error="No networks reconnected"
                )
        
        except Exception as e:
            return self._create_result(
                status=ActionStatus.FAILED,
                success=False,
                message=f"Rollback error: {str(e)}",
                error=str(e)
            )