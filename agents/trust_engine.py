"""
Progressive Trust Engine - Week 2, Days 5-7
Manages trust levels, decides auto vs. approval, handles feedback.

FIXED: 
1. Now passes incident resource to Containment Agent
2. Handles UNIQUE constraint errors with proper ID generation
3. Uses UUID for truly unique action IDs
"""

import asyncio
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import structlog

from config import config
from core import (
    queue, get_trust_metrics, update_trust_metrics, save_action_history,
    get_similar_actions, save_action, update_incident, ActionMode,
    TrustLevel, IncidentStatus, get_incident  # ← ADDED get_incident
)

log = structlog.get_logger()

@dataclass
class TrustLevelConfig:
    """Configuration for each trust level."""
    name: str
    confidence_threshold: Optional[float]
    action_range: tuple  # (min_actions, max_actions)
    requires_approval_for_p1: bool

TRUST_LEVELS = {
    1: TrustLevelConfig("Learning", None, (0, 50), True),
    2: TrustLevelConfig("Cautious", 0.95, (51, 150), True),
    3: TrustLevelConfig("Confident", 0.90, (151, 500), False),
    4: TrustLevelConfig("Autonomous", 0.85, (501, float('inf')), False)
}

class ApprovalManager:
    """Manages action approvals via terminal (and email in future)."""
    
    def __init__(self):
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}
        self.approval_timeout = 300  # 5 minutes
    
    async def request_approval(self, action_data: Dict[str, Any]) -> bool:
        """Request approval for an action. Returns True if approved."""
        action_id = action_data.get("action_id")
        incident_id = action_data.get("incident_id")
        
        self.pending_approvals[action_id] = {
            **action_data,
            "requested_at": datetime.utcnow().isoformat()
        }
        
        # Send approval request notification
        await queue.push("notification", {
            "type": "action_pending",
            "incident_id": incident_id,
            "action_id": action_id,
            "action_type": action_data.get("action_type"),
            "severity": action_data.get("severity", "P3"),
            "action_details": str(action_data.get("params", {})),
            "summary": f"Approval required for {action_data.get('action_type')}"
        })
        
        log.info("Approval requested", action_id=action_id, incident_id=incident_id)
        
        # In a real system, this would wait for webhook/email response
        # For demo, we'll use a simplified CLI approval
        return await self._wait_for_approval(action_id)
    
    async def _wait_for_approval(self, action_id: str, timeout: int = None) -> bool:
        """Wait for approval (simplified - checks Redis for approval signal)."""
        timeout = timeout or self.approval_timeout
        start = datetime.utcnow()
        
        while (datetime.utcnow() - start).seconds < timeout:
            # Check for approval in Redis
            try:
                approval = await queue.pop_nowait(f"approval:{action_id}")
                if approval:
                    approved = approval.get("approved", False)
                    self.pending_approvals.pop(action_id, None)
                    return approved
            except Exception:
                pass
            
            await asyncio.sleep(1)
        
        # Timeout - default to not approved
        log.warning("Approval timeout", action_id=action_id)
        self.pending_approvals.pop(action_id, None)
        return False
    
    async def approve(self, action_id: str, approved_by: str = "analyst"):
        """Approve an action (called externally)."""
        await queue.push(f"approval:{action_id}", {
            "approved": True,
            "approved_by": approved_by,
            "approved_at": datetime.utcnow().isoformat()
        })
    
    async def reject(self, action_id: str, rejected_by: str = "analyst", reason: str = ""):
        """Reject an action (called externally)."""
        await queue.push(f"approval:{action_id}", {
            "approved": False,
            "rejected_by": rejected_by,
            "reason": reason,
            "rejected_at": datetime.utcnow().isoformat()
        })

class ProgressiveTrustEngine:
    """Main trust engine that manages trust levels and decisions."""
    
    def __init__(self):
        self.approval_manager = ApprovalManager()
        self.running = False
    
    def generate_unique_action_id(self, incident_id: str, action_type: str) -> str:
        """Generate a unique action ID."""
        # Use first 4 chars of incident_id + timestamp + short UUID
        timestamp = int(datetime.utcnow().timestamp() * 1000) % 10000  # Last 4 digits of timestamp
        short_uuid = str(uuid.uuid4())[:8]
        return f"act-{incident_id[:4]}-{action_type[:4]}-{timestamp}-{short_uuid}"
    
    async def safe_save_action(self, action_data: Dict[str, Any], max_retries: int = 3) -> bool:
        """Safely save action with retry logic for UNIQUE constraint errors."""
        for attempt in range(max_retries):
            try:
                await save_action(action_data)
                return True
            except Exception as e:
                error_msg = str(e).lower()
                
                if "unique constraint failed" in error_msg:
                    # Generate new unique ID and retry
                    old_id = action_data.get("id")
                    new_id = self.generate_unique_action_id(
                        action_data.get("incident_id", "unknown"),
                        action_data.get("action_type", "unknown")
                    )
                    action_data["id"] = new_id
                    action_data["action_id"] = new_id  # Update both id fields
                    
                    log.warning("Action ID collision, retrying with new ID",
                              old_id=old_id,
                              new_id=new_id,
                              attempt=attempt + 1)
                    continue
                else:
                    # Other error, don't retry
                    log.error("Failed to save action", error=str(e), action_data=action_data)
                    return False
        
        log.error("Failed to save action after retries", action_data=action_data)
        return False
    
    async def start(self):
        """Start the trust engine."""
        self.running = True
        log.info("Progressive Trust Engine started")
        
        # Log current trust level
        metrics = await get_trust_metrics()
        level = metrics.get("current_level", 1)
        log.info("Current trust level", level=level, name=TRUST_LEVELS[level].name)
        
        await self._decision_loop()
    
    async def stop(self):
        """Stop the trust engine."""
        self.running = False
        log.info("Progressive Trust Engine stopped")
    
    async def _decision_loop(self):
        """Process trust decisions."""
        while self.running:
            try:
                decision_request = await queue.pop("trust_decision", timeout=5)
                
                if decision_request:
                    await self._make_decision(decision_request)
            except Exception as e:
                log.error("Error in trust decision", error=str(e))
                await asyncio.sleep(1)
    
    async def _make_decision(self, request: Dict[str, Any]):
        """Make trust decision for an incident's actions."""
        incident_id = request.get("incident_id")
        severity = request.get("severity", "P3")
        confidence = request.get("confidence", 0.5)
        actions = request.get("recommended_actions", [])
        
        log.info("Making trust decision", 
                 incident_id=incident_id, 
                 severity=severity,
                 confidence=confidence)
        
        # Get current trust metrics
        metrics = await get_trust_metrics()
        current_level = metrics.get("current_level", 1)
        total_actions = metrics.get("total_actions", 0)
        level_config = TRUST_LEVELS[current_level]
        
        # Determine action mode
        action_mode = await self._determine_mode(
            current_level, level_config, severity, confidence, actions
        )
        
        log.info("Trust decision made",
                 incident_id=incident_id,
                 level=current_level,
                 action_mode=action_mode.value)
        
        if action_mode == ActionMode.AUTO:
            # Auto-execute: push to containment queue
            await self._execute_auto(incident_id, actions, confidence)
        else:
            # Require approval
            await self._request_approval(incident_id, actions, severity)
        
        # Check if we should level up
        await self._check_level_change(metrics)
    
    async def _determine_mode(
        self,
        current_level: int,
        level_config: TrustLevelConfig,
        severity: str,
        confidence: float,
        actions: List[Dict]
    ) -> ActionMode:
        """Determine if actions should be auto-executed or require approval."""
        
        # Level 1: Everything needs approval
        if current_level == 1:
            return ActionMode.APPROVAL_REQUIRED
        
        # P1 incidents need higher trust or approval
        if severity == "P1" and level_config.requires_approval_for_p1:
            return ActionMode.APPROVAL_REQUIRED
        
        # Check confidence threshold
        if level_config.confidence_threshold and confidence < level_config.confidence_threshold:
            return ActionMode.APPROVAL_REQUIRED
        
        # Check historical success rate for similar actions
        for action in actions:
            similar = await get_similar_actions(action.get("action", "unknown"))
            if similar:
                success_count = sum(1 for a in similar if a.get("success"))
                success_rate = success_count / len(similar)
                
                if success_rate < 0.95:
                    log.info("Low success rate for action", 
                             action=action.get("action"),
                             success_rate=success_rate)
                    return ActionMode.APPROVAL_REQUIRED
        
        return ActionMode.AUTO
    
    async def _execute_auto(self, incident_id: str, actions: List[Dict], confidence: float):
        """Execute actions automatically."""
        await update_incident(incident_id, {"status": IncidentStatus.CONTAINMENT.value})
        
        # 🔥 FIX: Get incident details to extract resource
        incident = await get_incident(incident_id)
        
        if not incident:
            log.error("Incident not found for auto-execution", incident_id=incident_id)
            return
        
        # Extract resource and namespace from incident
        resource = incident.get("resource", "unknown")
        namespace = incident.get("namespace", "docker")
        
        log.debug("Auto-executing actions",
                 incident_id=incident_id,
                 resource=resource,
                 namespace=namespace,
                 actions_count=len(actions))
        
        successful_saves = 0
        for i, action in enumerate(actions):
            # Generate unique action ID
            action_id = self.generate_unique_action_id(incident_id, action.get("action", "unknown"))
            
            action_data = {
                "id": action_id,
                "incident_id": incident_id,
                "action_type": action.get("action"),
                "params": action.get("params", {}),
                "status": "auto_approved",
                # 🔥 FIX: Add resource and namespace from incident
                "resource": resource,
                "namespace": namespace
            }
            
            # Use safe save with retry logic
            if await self.safe_save_action(action_data):
                successful_saves += 1
                
                # Push to containment queue
                await queue.push("containment", {
                    **action_data,
                    "action_id": action_id,  # Ensure action_id is set
                    "confidence": confidence,
                    "auto_approved": True
                })
            else:
                log.error("Failed to save action for auto-execution", 
                         action_id=action_id, 
                         incident_id=incident_id)
        
        await queue.push("notification", {
            "type": "actions_auto_approved",
            "incident_id": incident_id,
            "severity": "P3",
            "actions_count": successful_saves,
            "summary": f"Auto-executing {successful_saves}/{len(actions)} containment actions on {resource}"
        })
    
    async def _request_approval(self, incident_id: str, actions: List[Dict], severity: str):
        """Request approval for actions."""
        await update_incident(incident_id, {"status": IncidentStatus.PENDING_APPROVAL.value})
        
        # 🔥 FIX: Get incident details
        incident = await get_incident(incident_id)
        
        if not incident:
            log.error("Incident not found for approval", incident_id=incident_id)
            return
        
        # Extract resource and namespace from incident
        resource = incident.get("resource", "unknown")
        namespace = incident.get("namespace", "docker")
        
        log.debug("Requesting approval for actions",
                 incident_id=incident_id,
                 resource=resource,
                 namespace=namespace,
                 actions_count=len(actions))
        
        successful_saves = 0
        for i, action in enumerate(actions):
            # Generate unique action ID
            action_id = self.generate_unique_action_id(incident_id, action.get("action", "unknown"))
            
            action_data = {
                "id": action_id,
                "action_id": action_id,
                "incident_id": incident_id,
                "action_type": action.get("action"),
                "params": action.get("params", {}),
                "status": "pending_approval",
                "severity": severity,
                # 🔥 FIX: Add resource and namespace
                "resource": resource,
                "namespace": namespace
            }
            
            # Use safe save with retry logic
            if await self.safe_save_action(action_data):
                successful_saves += 1
                
                # Request approval (non-blocking for demo)
                asyncio.create_task(self._handle_approval(action_data))
            else:
                log.error("Failed to save action for approval", 
                         action_id=action_id, 
                         incident_id=incident_id)
    
    async def _handle_approval(self, action_data: Dict[str, Any]):
        """Handle the approval process for a single action."""
        approved = await self.approval_manager.request_approval(action_data)
        
        if approved:
            # Push to containment queue
            await queue.push("containment", {
                **action_data,
                "status": "approved",
                "auto_approved": False
            })
            
            await queue.push("notification", {
                "type": "action_approved",
                "incident_id": action_data.get("incident_id"),
                "action_id": action_data.get("action_id"),
                "severity": "P3",
                "summary": f"Action {action_data.get('action_type')} approved for {action_data.get('resource')}"
            })
        else:
            await queue.push("notification", {
                "type": "action_rejected",
                "incident_id": action_data.get("incident_id"),
                "action_id": action_data.get("action_id"),
                "severity": "P3",
                "summary": f"Action {action_data.get('action_type')} rejected/timed out"
            })
    
    async def _check_level_change(self, metrics: Dict[str, Any]):
        """Check if trust level should change."""
        current_level = metrics.get("current_level", 1)
        total_actions = metrics.get("total_actions", 0)
        successful_actions = metrics.get("successful_actions", 0)
        
        # Calculate success rate
        success_rate = successful_actions / total_actions if total_actions > 0 else 0
        
        # Check for level up
        if current_level < 4:
            next_level_config = TRUST_LEVELS[current_level + 1]
            min_actions, _ = next_level_config.action_range
            
            if total_actions >= min_actions and success_rate >= 0.95:
                await self._level_up(current_level + 1)
        
        # Check for level down (safety guardrail)
        if current_level > 1:
            if success_rate < 0.90:
                await self._level_down(current_level - 1, "Success rate below 90%")
    
    async def _level_up(self, new_level: int):
        """Upgrade trust level."""
        level_config = TRUST_LEVELS[new_level]
        
        await update_trust_metrics({
            "current_level": new_level,
            "level_changed_at": datetime.utcnow().isoformat()
        })
        
        log.info("Trust level UPGRADED", new_level=new_level, name=level_config.name)
        
        await queue.push("notification", {
            "type": "trust_level_changed",
            "severity": "P4",
            "new_level": new_level,
            "level_name": level_config.name,
            "summary": f"Trust upgraded to Level {new_level}: {level_config.name}"
        })
    
    async def _level_down(self, new_level: int, reason: str):
        """Downgrade trust level."""
        level_config = TRUST_LEVELS[new_level]
        
        await update_trust_metrics({
            "current_level": new_level,
            "level_changed_at": datetime.utcnow().isoformat()
        })
        
        log.warning("Trust level DOWNGRADED", new_level=new_level, reason=reason)
        
        await queue.push("notification", {
            "type": "trust_level_changed",
            "severity": "P2",
            "new_level": new_level,
            "level_name": level_config.name,
            "reason": reason,
            "summary": f"Trust downgraded to Level {new_level}: {reason}"
        })
    
    async def record_action_result(self, action_type: str, incident_type: str, 
                                    success: bool, confidence: float,
                                    analyst_rating: int = None, feedback: str = None):
        """Record action result for trust calculation."""
        await save_action_history({
            "action_type": action_type,
            "incident_type": incident_type,
            "success": success,
            "confidence": confidence,
            "analyst_rating": analyst_rating,
            "feedback": feedback
        })
        
        # Update trust metrics
        metrics = await get_trust_metrics()
        updates = {
            "total_actions": metrics.get("total_actions", 0) + 1
        }
        
        if success:
            updates["successful_actions"] = metrics.get("successful_actions", 0) + 1
        else:
            updates["failed_actions"] = metrics.get("failed_actions", 0) + 1
        
        await update_trust_metrics(updates)
        log.debug("Action result recorded", action_type=action_type, success=success)

# Agent instance
trust_engine = ProgressiveTrustEngine()