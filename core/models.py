from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum
import uuid

class Severity(str, Enum):
    P1 = "P1"  # Critical
    P2 = "P2"  # High
    P3 = "P3"  # Medium
    P4 = "P4"  # Low

class IncidentStatus(str, Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    PENDING_APPROVAL = "pending_approval"
    CONTAINMENT = "containment"
    INVESTIGATING = "investigating"
    RECOVERING = "recovering"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"

class ActionMode(str, Enum):
    AUTO = "AUTO"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"

class TrustLevel(int, Enum):
    LEARNING = 1
    CAUTIOUS = 2
    CONFIDENT = 3
    AUTONOMOUS = 4

class Incident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    type: str
    severity: Severity = Severity.P4
    status: IncidentStatus = IncidentStatus.DETECTED
    source: Optional[str] = None
    resource: Optional[str] = None
    namespace: Optional[str] = None
    raw_event: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ReasoningStep(BaseModel):
    type: str  # observation, analysis, hypothesis, conclusion
    content: str
    confidence: Optional[float] = None

class EnrichedIncident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    incident_id: str
    severity: Severity
    confidence: float
    recommended_actions: List[Dict[str, Any]]
    action_mode: ActionMode
    reasoning_chain: List[ReasoningStep]
    context: Dict[str, Any] = Field(default_factory=dict)

class Action(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    incident_id: str
    action_type: str
    params: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    result: Optional[Dict[str, Any]] = None

class TrustMetrics(BaseModel):
    total_actions: int = 0
    successful_actions: int = 0
    failed_actions: int = 0
    current_level: TrustLevel = TrustLevel.LEARNING
    success_rate: float = 0.0

class Notification(BaseModel):
    incident_id: Optional[str] = None
    channel: str  # email, terminal
    message: str
    status: str = "pending"
    sent_at: Optional[datetime] = None
