"""
Action Registry - Plugin system for action executors.

Executors can self-register using the @action_executor decorator.
"""

from typing import Dict, Type, List, Optional
import structlog

log = structlog.get_logger()


class ActionRegistry:
    """
    Central registry for action executors.
    
    Usage:
        @action_executor("delete_pod")
        class DeletePodExecutor(BaseActionExecutor):
            ...
    """
    
    _executors: Dict[str, Type] = {}
    _capabilities: Dict[str, 'ActionCapability'] = {}
    
    @classmethod
    def register(cls, action_name: str, executor_class: Type):
        """
        Register an action executor.
        
        Args:
            action_name: Name of the action (e.g., "delete_pod")
            executor_class: Executor class implementing BaseActionExecutor
        """
        if action_name in cls._executors:
            log.warning("Action executor already registered, overwriting",
                       action_name=action_name,
                       old_class=cls._executors[action_name].__name__,
                       new_class=executor_class.__name__)
        
        cls._executors[action_name] = executor_class
        
        # Extract capability if available
        if hasattr(executor_class, 'get_capability'):
            try:
                capability = executor_class.get_capability()
                cls._capabilities[action_name] = capability
            except Exception as e:
                log.error("Failed to get capability", 
                         action_name=action_name, 
                         error=str(e))
        
        log.debug("Action executor registered",
                 action_name=action_name,
                 class_name=executor_class.__name__)
    
    @classmethod
    def get(cls, action_name: str) -> Optional[Type]:
        """
        Get executor class by action name.
        
        Args:
            action_name: Name of the action
            
        Returns:
            Executor class or None if not found
        """
        return cls._executors.get(action_name)
    
    @classmethod
    def has(cls, action_name: str) -> bool:
        """Check if action is registered."""
        return action_name in cls._executors
    
    @classmethod
    def list_available(cls) -> List[str]:
        """Get list of all registered action names."""
        return sorted(cls._executors.keys())
    
    @classmethod
    def get_capabilities(cls) -> Dict[str, 'ActionCapability']:
        """Get capabilities of all registered actions."""
        return cls._capabilities.copy()
    
    @classmethod
    def get_capability(cls, action_name: str) -> Optional['ActionCapability']:
        """Get capability of a specific action."""
        return cls._capabilities.get(action_name)
    
    @classmethod
    def clear(cls):
        """Clear registry (useful for testing)."""
        cls._executors.clear()
        cls._capabilities.clear()
    
    @classmethod
    def get_stats(cls) -> Dict[str, any]:
        """Get registry statistics."""
        return {
            'total_executors': len(cls._executors),
            'actions': cls.list_available(),
            'destructive_count': sum(
                1 for cap in cls._capabilities.values() 
                if cap.destructive
            ),
            'reversible_count': sum(
                1 for cap in cls._capabilities.values() 
                if cap.reversible
            )
        }


def action_executor(action_name: str):
    """
    Decorator to auto-register action executors.
    
    Usage:
        @action_executor("delete_pod")
        class DeletePodExecutor(BaseActionExecutor):
            ...
    """
    def decorator(cls):
        ActionRegistry.register(action_name, cls)
        return cls
    return decorator
