"""
Base Action Executor - Windows-compatible using Docker CLI.
Uses subprocess like the attack simulator.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
import uuid
import json
import subprocess
from datetime import datetime
import structlog

from config import config
from .models import ActionResult, ActionStatus, ForensicSnapshot, ActionCapability

log = structlog.get_logger()


class BaseActionExecutor(ABC):
    """
    Abstract base class for all action executors.
    Windows-compatible: Uses Docker CLI instead of docker-py library.
    """
    
    # Metadata (must be set by subclasses)
    action_name: str = "base_action"
    description: str = "Base action executor"
    destructive: bool = False
    requires_snapshot: bool = False
    reversible: bool = False
    
    def __init__(self):
        """Initialize executor with Docker CLI."""
        try:
            result = subprocess.run(
                ['docker', 'version'],
                capture_output=True,
                text=True,
                check=True,
                timeout=5
            )
            self.docker_available = True
            log.info("Docker CLI available")
        except Exception as e:
            log.error("Docker CLI unavailable", error=str(e))
            self.docker_available = False
    
    def _run_docker_command(self, args: list, check=True) -> tuple[bool, str, str]:
        """
        Run docker command and return (success, stdout, stderr).
        
        Args:
            args: Command arguments (e.g., ['ps', '-a'])
            check: Raise exception on non-zero exit
            
        Returns:
            (success, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ['docker'] + args,
                capture_output=True,
                text=True,
                check=check,
                timeout=30
            )
            return True, result.stdout.strip(), result.stderr.strip()
        except subprocess.CalledProcessError as e:
            return False, e.stdout.strip() if e.stdout else "", e.stderr.strip() if e.stderr else ""
        except subprocess.TimeoutExpired:
            return False, "", "Command timed out"
        except Exception as e:
            return False, "", str(e)
    
    @classmethod
    def get_capability(cls) -> ActionCapability:
        """Get capability description for this executor."""
        return ActionCapability(
            action_name=cls.action_name,
            description=cls.description,
            destructive=cls.destructive,
            requires_snapshot=cls.requires_snapshot,
            reversible=cls.reversible,
            required_params=cls.get_required_params(),
            optional_params=cls.get_optional_params()
        )
    
    @classmethod
    def get_required_params(cls) -> list:
        """Override to specify required parameters."""
        return []
    
    @classmethod
    def get_optional_params(cls) -> list:
        """Override to specify optional parameters."""
        return []
    
    # =========================================================================
    # VALIDATION
    # =========================================================================
    
    @abstractmethod
    async def validate_params(self, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate action parameters."""
        pass
    
    @abstractmethod
    async def validate_preconditions(self, resource: str, params: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate that action can be executed."""
        pass
    
    # =========================================================================
    # FORENSIC SNAPSHOT
    # =========================================================================
    
    async def capture_snapshot(
        self, 
        incident_id: str,
        resource: str, 
        namespace: str
    ) -> Optional[ForensicSnapshot]:
        """Capture forensic snapshot before destructive actions."""
        if not self.requires_snapshot:
            return None
        
        snapshot_id = f"snap-{uuid.uuid4().hex[:12]}"
        
        log.info("Capturing forensic snapshot",
                snapshot_id=snapshot_id,
                resource=resource)
        
        try:
            snapshot = ForensicSnapshot(
                snapshot_id=snapshot_id,
                incident_id=incident_id,
                action_type=self.action_name,
                resource=resource,
                namespace=namespace
            )
            
            # Get container name
            container_name = self._extract_container_name(resource)
            
            # Check if container exists
            if not self._container_exists(container_name):
                log.warning("Container not found for snapshot", resource=resource)
                return None
            
            # Capture logs
            try:
                success, logs, _ = self._run_docker_command(['logs', '--tail', '1000', container_name], check=False)
                if success:
                    snapshot.container_logs = logs[:50000]  # Limit size
            except Exception as e:
                log.warning("Failed to capture logs", error=str(e))
            
            # Capture container inspect
            try:
                success, inspect_json, _ = self._run_docker_command(['inspect', container_name], check=False)
                if success:
                    snapshot.container_inspect = json.loads(inspect_json)[0]
            except Exception as e:
                log.warning("Failed to inspect container", error=str(e))
            
            # Capture environment (from inspect)
            try:
                if snapshot.container_inspect:
                    env_vars = snapshot.container_inspect.get('Config', {}).get('Env', [])
                    filtered_env = {}
                    sensitive_keys = ['PASSWORD', 'SECRET', 'TOKEN', 'KEY', 'API']
                    
                    for env_pair in env_vars:
                        if '=' in env_pair:
                            key, value = env_pair.split('=', 1)
                            if any(s in key.upper() for s in sensitive_keys):
                                filtered_env[key] = "[REDACTED]"
                            else:
                                filtered_env[key] = value[:100]
                    
                    snapshot.environment_vars = filtered_env
            except Exception as e:
                log.warning("Failed to capture environment", error=str(e))
            
            snapshot_data = snapshot.model_dump_json()
            snapshot.size_bytes = len(snapshot_data.encode('utf-8'))
            
            log.info("Forensic snapshot captured",
                    snapshot_id=snapshot_id,
                    size_bytes=snapshot.size_bytes)
            
            return snapshot
            
        except Exception as e:
            log.error("Failed to capture snapshot",
                     snapshot_id=snapshot_id,
                     error=str(e))
            return None
    
    # =========================================================================
    # EXECUTION
    # =========================================================================
    
    @abstractmethod
    async def execute(
        self, 
        incident_id: str,
        resource: str,
        params: Dict[str, Any]
    ) -> ActionResult:
        """Execute the action."""
        pass
    
    # =========================================================================
    # IVAM VALIDATION - 3 PHASES
    # =========================================================================
    
    @abstractmethod
    async def verify_immediate(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        IVAM Phase 1: Immediate verification (30 seconds).
        Check if the action completed successfully.
        
        Returns:
            (success, message)
        """
        pass
    
    async def verify_sustained(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        IVAM Phase 2: Sustained verification (5 minutes).
        Check if containment is still holding after initial success.
        Default: Re-run Phase 1 check after delay.
        
        Override this if different logic is needed.
        
        Returns:
            (success, message)
        """
        # Default implementation: wait 5 minutes then re-check Phase 1
        import asyncio
        await asyncio.sleep(300)  # 5 minutes
        return await self.verify_immediate(resource, result)
    
    async def verify_effective(
        self,
        resource: str,
        result: ActionResult
    ) -> tuple[bool, str]:
        """
        IVAM Phase 3: Effectiveness verification.
        Check if threat behavior has actually stopped.
        Default: Return True if Phase 1 & 2 passed.
        
        Override this to check threat-specific indicators (CPU, network, etc.)
        
        Returns:
            (success, message)
        """
        # Default: if Phase 1 & 2 passed, assume effective
        return True, "Action completed and sustained - assuming effective"
    
    def get_fallback_actions(self, action_params: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Get fallback actions if this action fails validation.
        Returns list of action definitions in escalation order.
        
        Override this to provide intelligent fallback strategies.
        
        Returns:
            List of action dicts: [{"action": "...", "params": {...}}, ...]
        """
        return []  # No fallback by default
    
    # =========================================================================
    # ROLLBACK (Optional)
    # =========================================================================
    
    async def rollback(
        self,
        resource: str,
        params: Dict[str, Any],
        original_result: ActionResult
    ) -> ActionResult:
        """Rollback action if needed."""
        if not self.reversible:
            return ActionResult(
                action_type=f"{self.action_name}_rollback",
                status=ActionStatus.FAILED,
                success=False,
                message="Action is not reversible"
            )
        
        return ActionResult(
            action_type=f"{self.action_name}_rollback",
            status=ActionStatus.FAILED,
            success=False,
            message="Rollback not implemented"
        )
    
    # =========================================================================
    # UTILITIES
    # =========================================================================
    
    def _extract_container_name(self, resource: str) -> str:
        """Extract container name from resource string."""
        # Strip "container/" prefix if present
        if resource.startswith("container/"):
            return resource.replace("container/", "", 1)
        return resource
    
    def _container_exists(self, container_name: str) -> bool:
        """Check if container exists."""
        if not self.docker_available:
            return False
        
        try:
            # List all containers and search for name
            success, stdout, _ = self._run_docker_command(
                ['ps', '-a', '--format', '{{.Names}}'],
                check=False
            )
            
            if success:
                containers = stdout.split('\n')
                # Exact match or partial match
                for c in containers:
                    if c == container_name or container_name in c or c in container_name:
                        return True
            
            return False
            
        except Exception as e:
            log.error("Error checking container", error=str(e))
            return False
    
    def _get_container_status(self, container_name: str) -> Optional[str]:
        """Get container status."""
        try:
            success, stdout, _ = self._run_docker_command(
                ['ps', '-a', '--filter', f'name={container_name}', '--format', '{{.Status}}'],
                check=False
            )
            
            if success and stdout:
                # Parse status (e.g., "Up 2 minutes" or "Exited (0) 1 minute ago")
                status_parts = stdout.lower().split()
                if status_parts:
                    return status_parts[0]  # "up", "exited", "created", etc.
            
            return None
            
        except Exception:
            return None
    
    def _create_result(
        self,
        status: ActionStatus,
        success: bool,
        message: str,
        **kwargs
    ) -> ActionResult:
        """Helper to create ActionResult."""
        result = ActionResult(
            action_type=self.action_name,
            status=status,
            success=success,
            message=message,
            simulated=config.DRY_RUN,
            **kwargs
        )
        result.mark_completed()
        return result