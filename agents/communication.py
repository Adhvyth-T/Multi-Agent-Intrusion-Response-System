"""
Communication Agent - Week 1, Days 6-7
Sends alerts via Email (SMTP) and Terminal.
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, Optional
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import structlog

from config import config
from core import queue, save_notification

log = structlog.get_logger()

# Notification templates
TEMPLATES = {
    "incident_detected": {
        "subject": "🚨 [{severity}] Security Incident Detected - {incident_id}",
        "body": """
Security Incident Alert
=======================

Incident ID: {incident_id}
Severity: {severity}
Threat Type: {threat_type}
Resource: {resource}
Time: {timestamp}

Summary:
{summary}

---
Autonomous IR System
"""
    },
    "triage_complete": {
        "subject": "📋 [{severity}] Incident Triaged - {incident_id}",
        "body": """
Incident Triage Complete
========================

Incident ID: {incident_id}
Severity: {severity}
Confidence: {confidence:.1%}
Action Mode: {action_mode}

Recommended Actions:
{actions}

Reasoning Summary:
{reasoning_summary}

---
Autonomous IR System
"""
    },
    "action_pending": {
        "subject": "⏳ Action Approval Required - {incident_id}",
        "body": """
Action Approval Required
========================

Incident ID: {incident_id}
Action: {action_type}

The progressive trust system requires manual approval for this action.

To approve, respond to this email with "APPROVE {action_id}"
To reject, respond with "REJECT {action_id}"

Action Details:
{action_details}

---
Autonomous IR System
"""
    },
    "action_executed": {
        "subject": "✅ Action Executed - {incident_id}",
        "body": """
Containment Action Executed
===========================

Incident ID: {incident_id}
Action: {action_type}
Status: {status}

Result:
{result}

---
Autonomous IR System
"""
    },
    "incident_resolved": {
        "subject": "✅ Incident Resolved - {incident_id}",
        "body": """
Incident Resolved
=================

Incident ID: {incident_id}
Total Time: {duration}
Actions Taken: {actions_count}

Summary:
{summary}

---
Autonomous IR System
"""
    }
}

class EmailNotifier:
    """Send notifications via SMTP."""
    
    def __init__(self):
        self.configured = all([
            config.smtp_host,
            config.smtp_user,
            config.smtp_password,
            config.alert_email
        ])
        if not self.configured:
            log.warning("Email notifications not configured - missing SMTP settings")
    
    async def send(self, to: str, subject: str, body: str) -> bool:
        """Send email notification."""
        if not self.configured:
            log.debug("Email skipped - not configured")
            return False
        
        try:
            message = MIMEMultipart()
            message["From"] = config.smtp_user
            message["To"] = to
            message["Subject"] = subject
            message.attach(MIMEText(body, "plain"))
            
            await aiosmtplib.send(
                message,
                hostname=config.smtp_host,
                port=config.smtp_port,
                username=config.smtp_user,
                password=config.smtp_password,
                start_tls=True
            )
            log.info("Email sent", to=to, subject=subject[:50])
            return True
        except Exception as e:
            log.error("Failed to send email", error=str(e))
            return False

class TerminalNotifier:
    """Send notifications to terminal (always available)."""
    
    COLORS = {
        "P1": "\033[91m",  # Red
        "P2": "\033[93m",  # Yellow
        "P3": "\033[94m",  # Blue
        "P4": "\033[92m",  # Green
        "reset": "\033[0m",
        "bold": "\033[1m"
    }
    
    def notify(self, notification: Dict[str, Any]):
        """Print notification to terminal."""
        severity = notification.get("severity", "P4")
        color = self.COLORS.get(severity, "")
        reset = self.COLORS["reset"]
        bold = self.COLORS["bold"]
        
        notif_type = notification.get("type", "unknown")
        
        print(f"\n{color}{bold}{'='*60}{reset}")
        print(f"{color}{bold}[{severity}] {notif_type.upper().replace('_', ' ')}{reset}")
        print(f"{color}{'='*60}{reset}")
        
        for key, value in notification.items():
            if key not in ["type", "severity"]:
                print(f"  {key}: {value}")
        
        print(f"{color}{'='*60}{reset}\n")

class CommunicationAgent:
    """Main communication agent handling all notifications."""
    
    def __init__(self):
        self.email = EmailNotifier()
        self.terminal = TerminalNotifier()
        self.running = False
    
    async def start(self):
        """Start the communication agent."""
        self.running = True
        log.info("Communication Agent started")
        
        await self._notification_loop()
    
    async def stop(self):
        """Stop the communication agent."""
        self.running = False
        log.info("Communication Agent stopped")
    
    async def _notification_loop(self):
        """Process notification queue."""
        while self.running:
            try:
                notification = await queue.pop("notification", timeout=5)
                
                if notification:
                    await self._process_notification(notification)
            except Exception as e:
                log.error("Error processing notification", error=str(e))
                await asyncio.sleep(1)
    
    async def _process_notification(self, notification: Dict[str, Any]):
        """Process and send notification through all channels."""
        notif_type = notification.get("type", "unknown")
        timestamp = datetime.utcnow().isoformat()
        notification["timestamp"] = timestamp
        
        # Always send to terminal
        self.terminal.notify(notification)
        
        # Try to send email
        template = TEMPLATES.get(notif_type)
        if template and config.alert_email:
            # Format subject - notification already contains timestamp
            subject = template["subject"].format(**notification)
            
            # Format body
            body_data = notification.copy()
            
            # Handle special formatting for certain fields
            if "actions" in body_data and isinstance(body_data["actions"], list):
                body_data["actions"] = "\n".join(
                    f"  - {a.get('action', a)}" for a in body_data["actions"]
                )
            
            # Add default values for missing fields
            defaults = {
                "incident_id": "N/A",
                "severity": "Unknown",
                "threat_type": "Unknown",
                "resource": "Unknown",
                "summary": "No summary available",
                "confidence": 0.0,
                "action_mode": "Unknown",
                "reasoning_summary": "No reasoning available",
                "action_type": "Unknown",
                "status": "Unknown",
                "result": "No result available",
                "duration": "Unknown",
                "actions_count": 0,
                "action_id": "N/A",
                "action_details": "No details available"
            }
            
            # Merge defaults with body_data (body_data takes precedence)
            for key, value in defaults.items():
                if key not in body_data:
                    body_data[key] = value
            
            try:
                body = template["body"].format(**body_data)
            except KeyError as e:
                log.error("Missing template key", key=str(e), notification_type=notif_type)
                body = f"Error formatting notification: missing key {e}"
            
            email_sent = await self.email.send(config.alert_email, subject, body)
            
            # Save notification record
            await save_notification({
                "incident_id": notification.get("incident_id"),
                "channel": "email",
                "message": subject,
                "status": "sent" if email_sent else "failed",
                "sent_at": timestamp if email_sent else None
            })
        
        # Save terminal notification
        await save_notification({
            "incident_id": notification.get("incident_id"),
            "channel": "terminal",
            "message": f"[{notif_type}] {notification.get('summary', '')}",
            "status": "sent",
            "sent_at": timestamp
        })
        
        # Publish real-time update
        await queue.publish("live_updates", notification)
    
    async def send_immediate(self, notification: Dict[str, Any]):
        """Send notification immediately (bypass queue)."""
        await self._process_notification(notification)

# Agent instance
communication_agent = CommunicationAgent()