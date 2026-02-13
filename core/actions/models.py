"""
Action execution models and data structures.
"""

from enum import Enum
from typing import Dict, Any, Optional, List
from datetime import datetime
from pydantic import BaseModel, Field


class ActionStatus(str, Enum):
    """Status of an action execution."""
    PENDING = "pending"
    VALIDATING = "validating"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    PARTIAL = "partial"  # Some steps succeeded
    ROLLED_BACK = "rolled_back"
    SIMULATED = "simulated"  # Dry-run mode


class ActionResult(BaseModel):
    """Result of an action execution."""
    action_type: str
    status: ActionStatus
    success: bool
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    
    # Execution metadata
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    
    # Forensics
    snapshot_id: Optional[str] = None
    snapshot_location: Optional[str] = None
    
    # Verification
    verified_immediate: bool = False
    verification_details: Dict[str, Any] = Field(default_factory=dict)
    
    # Error handling
    error: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    rollback_needed: bool = False
    
    # Simulation
    simulated: bool = False
    
    def mark_completed(self):
        """Mark action as completed and calculate duration."""
        self.completed_at = datetime.utcnow()
        if self.started_at:
            delta = self.completed_at - self.started_at
            self.duration_seconds = delta.total_seconds()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode='json')


class ForensicSnapshot(BaseModel):
    """Forensic snapshot captured before destructive actions."""
    snapshot_id: str
    incident_id: str
    action_type: str
    resource: str
    namespace: str
    
    # Captured data
    container_logs: Optional[str] = None
    container_inspect: Optional[Dict[str, Any]] = None
    network_connections: Optional[List[Dict[str, Any]]] = None
    environment_vars: Optional[Dict[str, str]] = None
    process_list: Optional[List[Dict[str, Any]]] = None
    filesystem_checksums: Optional[Dict[str, str]] = None
    
    # Metadata
    captured_at: datetime = Field(default_factory=datetime.utcnow)
    storage_location: Optional[str] = None
    size_bytes: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return self.model_dump(mode='json')


class ActionCapability(BaseModel):
    """Describes what an action executor can do."""
    action_name: str
    description: str
    
    # Characteristics
    destructive: bool = False
    requires_snapshot: bool = False
    reversible: bool = False
    
    # Parameters
    required_params: List[str] = Field(default_factory=list)
    optional_params: List[str] = Field(default_factory=list)
    
    # Constraints
    supported_platforms: List[str] = Field(default_factory=lambda: ["docker", "kubernetes"])
    min_trust_level: int = 1
    
    # Timing
    estimated_duration_seconds: Optional[int] = None
    timeout_seconds: int = 300
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self.model_dump(mode='json')


class ValidationResult(BaseModel):
    """Result of action validation (IVAM)."""
    action_id: str
    phase: str  # "immediate", "sustained", "effective"
    success: bool
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)
    validated_at: datetime = Field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return self.model_dump(mode='json')
