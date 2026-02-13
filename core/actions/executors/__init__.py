"""
Action Executors - Auto-import all executors to trigger registration.

This module automatically imports all executor classes, which triggers
their @action_executor decorators to register them in the ActionRegistry.
"""

# Import all executors to trigger @action_executor decorator
from .delete_pod import DeletePodExecutor
from .network_isolate import NetworkIsolateExecutor
from .pause_container import PauseContainerExecutor
from .restart_container import RestartContainerExecutor

# Export for convenience
__all__ = [
    'DeletePodExecutor',
    'NetworkIsolateExecutor',
    'PauseContainerExecutor',
    'RestartContainerExecutor',
]
