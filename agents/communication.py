"""
Communication Agent - Week 1, Days 6-7 (Enhanced + Fixed)
Sends alerts via Email (SMTP) and Terminal.
Reads email replies for action approvals/rejections and pushes to approval queue.
Includes HTML email templates with plain-text fallback.

BUG FIX: The original enhanced version had a silent email-drop bug in
_process_notification. It only sent email when html_body was truthy AND fell
back to plain only when "channels": ["email"] was explicitly set on the
notification dict. Since DecisionAgent never sets that key, action_pending
(and others) were silently dropped after HTML rendered fine but the fallback
gate was never entered.

FIX: Always try both HTML and plain-text templates. Send if either produces
content. This matches the reliability of the original TEMPLATES-dict approach
while keeping the beautiful HTML emails.

NEW TEMPLATES ADDED vs original enhanced version:
  - containment_retries_exhausted  (HTML existed, plain was missing)
  All plain-text PLAIN_TEMPLATES now mirror every HTML template 1:1.
"""

import asyncio
import re
import email
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
import aiosmtplib
import aioimaplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import structlog

from config import config
from core import queue, save_notification

log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Plain-text fallback templates
# One entry for every HTML template. Used when HTML fails AND as the
# plain-text part of multipart/alternative messages.
# ---------------------------------------------------------------------------
PLAIN_TEMPLATES = {
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
""",
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
""",
    },
    "action_pending": {
        "subject": "⏳ [{severity}] Action Approval Required - {incident_id} [{action_id}]",
        "body": """
Action Approval Required
========================
Incident ID:  {incident_id}
Action ID:    {action_id}
Action Type:  {action_type}
Severity:     {severity}

The progressive trust system requires manual approval for this action.

──────────────────────────────────────────
To APPROVE, reply with:
  APPROVE {action_id}

To REJECT, reply with:
  REJECT {action_id}
──────────────────────────────────────────

Action Details:
{action_details}

---
Autonomous IR System
""",
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
""",
    },
    "action_failed": {
        "subject": "❌ Action Failed - {incident_id}",
        "body": """
Containment Action Failed
=========================
Incident ID: {incident_id}
Action ID:   {action_id}
Action Type: {action_type}
Severity:    {severity}

Error:
{error}

Summary:
{summary}

---
Autonomous IR System
""",
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
""",
    },
    "containment_retries_exhausted": {
        "subject": "🚨 CRITICAL: Containment Failed After {max_retries} Attempts - {incident_id}",
        "body": """
Containment Failure — HUMAN INTERVENTION REQUIRED
==================================================
Incident ID: {incident_id}
Resource:    {resource}
Retries:     {max_retries}
Time:        {timestamp}

⚠ Automated containment exhausted — manual action required.

Situation Summary:
{summary}

---
Autonomous IR System
""",
    },
}

# Defaults for every placeholder referenced in any template
_TEMPLATE_DEFAULTS: Dict[str, Any] = {
    "incident_id":       "N/A",
    "severity":          "Unknown",
    "threat_type":       "Unknown",
    "resource":          "Unknown",
    "summary":           "No summary available",
    "confidence":        0.0,
    "action_mode":       "Unknown",
    "reasoning_summary": "No reasoning available",
    "action_type":       "Unknown",
    "status":            "Unknown",
    "result":            "No result available",
    "duration":          "Unknown",
    "actions_count":     0,
    "action_id":         "N/A",
    "action_details":    "No details available",
    "error":             "Unknown error",
    "actions":           "None",
    "max_retries":       "N/A",
    "timestamp":         "",
}


def _render_plain_template(template: Dict[str, str], data: Dict[str, Any]) -> Tuple[str, str]:
    """Render subject + body from a plain-text template dict."""
    render_data = data.copy()

    # Convert action list to readable text
    if "actions" in render_data and isinstance(render_data["actions"], list):
        render_data["actions"] = "\n".join(
            f"  - {a.get('action', a) if isinstance(a, dict) else a}"
            for a in render_data["actions"]
        )

    for key, value in _TEMPLATE_DEFAULTS.items():
        render_data.setdefault(key, value)

    try:
        subject = template["subject"].format(**render_data)
    except (KeyError, ValueError) as e:
        log.error("Missing subject template key", key=str(e), type=data.get("type"))
        subject = f"[IR] Notification - {data.get('incident_id', 'N/A')}"

    try:
        body = template["body"].format(**render_data)
    except (KeyError, ValueError) as e:
        log.error("Missing body template key", key=str(e), type=data.get("type"))
        body = (
            f"Error rendering notification body (missing key: {e}).\n\n"
            f"Raw data:\n{render_data}"
        )

    return subject, body


# ---------------------------------------------------------------------------
# HTML Email Templates
# ---------------------------------------------------------------------------
_BASE_STYLE = """
<style>
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: #0a0d14; font-family: 'IBM Plex Sans', -apple-system, sans-serif; color: #c8cdd8; -webkit-font-smoothing: antialiased; }
  .wrapper { max-width: 620px; margin: 0 auto; padding: 32px 16px; }
  .card { background: #111520; border-radius: 12px; overflow: hidden; border: 1px solid #1e2535; box-shadow: 0 24px 64px rgba(0,0,0,.6); }
  .header { padding: 28px 32px 24px; border-bottom: 1px solid #1e2535; }
  .header-row { display: flex; align-items: center; justify-content: space-between; }
  .brand { font-family: 'IBM Plex Mono', monospace; font-size: 11px; font-weight: 600; letter-spacing: .15em; text-transform: uppercase; color: #4a5568; }
  .badge { display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px; border-radius: 999px; font-family: 'IBM Plex Mono', monospace; font-size: 11px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase; }
  .badge-dot { width: 6px; height: 6px; border-radius: 50%; }
  .sev-P1 { background: rgba(239,68,68,.12); color: #f87171; border: 1px solid rgba(239,68,68,.3); }
  .sev-P1 .badge-dot { background: #ef4444; box-shadow: 0 0 6px #ef4444; }
  .sev-P2 { background: rgba(245,158,11,.12); color: #fbbf24; border: 1px solid rgba(245,158,11,.3); }
  .sev-P2 .badge-dot { background: #f59e0b; box-shadow: 0 0 6px #f59e0b; }
  .sev-P3 { background: rgba(99,102,241,.12); color: #818cf8; border: 1px solid rgba(99,102,241,.3); }
  .sev-P3 .badge-dot { background: #6366f1; box-shadow: 0 0 6px #6366f1; }
  .sev-P4 { background: rgba(34,197,94,.12); color: #4ade80; border: 1px solid rgba(34,197,94,.3); }
  .sev-P4 .badge-dot { background: #22c55e; box-shadow: 0 0 6px #22c55e; }
  .title { margin-top: 16px; font-size: 22px; font-weight: 600; color: #e8ecf4; line-height: 1.3; }
  .subtitle { margin-top: 4px; font-size: 13px; color: #4a5568; }
  .body { padding: 28px 32px; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 24px; }
  .meta-cell { background: #0d1117; border: 1px solid #1e2535; border-radius: 8px; padding: 12px 14px; }
  .meta-label { font-size: 10px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; color: #4a5568; margin-bottom: 4px; }
  .meta-value { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: #c8cdd8; word-break: break-all; }
  .section { margin-bottom: 20px; }
  .section-label { font-size: 10px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase; color: #4a5568; margin-bottom: 8px; }
  .section-body { background: #0d1117; border: 1px solid #1e2535; border-radius: 8px; padding: 14px 16px; font-size: 13.5px; line-height: 1.65; color: #a0aec0; }
  .approval-box { border-radius: 10px; border: 1px solid rgba(99,102,241,.35); background: rgba(99,102,241,.07); padding: 20px 24px; margin-bottom: 20px; }
  .approval-title { font-size: 13px; font-weight: 600; color: #818cf8; margin-bottom: 14px; letter-spacing: .04em; }
  .approval-row { display: flex; gap: 12px; }
  .cmd-block { flex: 1; background: #0d1117; border: 1px solid #1e2535; border-radius: 8px; padding: 12px 14px; }
  .cmd-label { font-size: 10px; font-weight: 600; letter-spacing: .1em; text-transform: uppercase; margin-bottom: 6px; }
  .cmd-label.approve { color: #4ade80; }
  .cmd-label.reject  { color: #f87171; }
  .cmd-text { font-family: 'IBM Plex Mono', monospace; font-size: 13px; color: #e8ecf4; letter-spacing: .04em; }
  .status-banner { display: flex; align-items: center; gap: 10px; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 13px; font-weight: 500; }
  .status-banner.success { background: rgba(34,197,94,.1); border: 1px solid rgba(34,197,94,.25); color: #4ade80; }
  .status-banner.error   { background: rgba(239,68,68,.1); border: 1px solid rgba(239,68,68,.25); color: #f87171; }
  .status-banner.warning { background: rgba(245,158,11,.1); border: 1px solid rgba(245,158,11,.25); color: #fbbf24; }
  .status-icon { font-size: 16px; }
  .actions-list { background: #0d1117; border: 1px solid #1e2535; border-radius: 8px; overflow: hidden; margin-bottom: 4px; }
  .action-item { display: flex; align-items: flex-start; gap: 10px; padding: 10px 14px; border-bottom: 1px solid #1a2030; font-size: 13px; color: #a0aec0; }
  .action-item:last-child { border-bottom: none; }
  .action-bullet { width: 6px; height: 6px; border-radius: 50%; background: #6366f1; margin-top: 5px; flex-shrink: 0; }
  .stat-strip { display: flex; border: 1px solid #1e2535; border-radius: 8px; overflow: hidden; margin-bottom: 20px; }
  .stat-cell { flex: 1; padding: 14px; text-align: center; border-right: 1px solid #1e2535; background: #0d1117; }
  .stat-cell:last-child { border-right: none; }
  .stat-num { font-family: 'IBM Plex Mono', monospace; font-size: 20px; font-weight: 600; color: #818cf8; }
  .stat-lbl { font-size: 10px; text-transform: uppercase; letter-spacing: .1em; color: #4a5568; margin-top: 3px; }
  .footer { padding: 18px 32px; border-top: 1px solid #1e2535; display: flex; align-items: center; justify-content: space-between; }
  .footer-brand { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #2d3748; letter-spacing: .1em; text-transform: uppercase; }
  .footer-ts { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #2d3748; }
</style>
"""

def _html_wrap(header_html: str, body_html: str, timestamp: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">{_BASE_STYLE}</head>
<body>
<div class="wrapper"><div class="card">
  {header_html}
  <div class="body">{body_html}</div>
  <div class="footer">
    <span class="footer-brand">Autonomous IR System</span>
    <span class="footer-ts">{timestamp}</span>
  </div>
</div></div>
</body></html>"""

def _header(icon: str, title: str, subtitle: str, severity: str) -> str:
    sev_cls = f"sev-{severity}" if severity in ("P1", "P2", "P3", "P4") else "sev-P4"
    return f"""
  <div class="header">
    <div class="header-row">
      <span class="brand">Autonomous IR · Security Platform</span>
      <span class="badge {sev_cls}"><span class="badge-dot"></span>{severity}</span>
    </div>
    <div class="title">{icon} {title}</div>
    <div class="subtitle">{subtitle}</div>
  </div>"""

def _meta_grid(**kwargs) -> str:
    cells = "".join(
        f'<div class="meta-cell"><div class="meta-label">{k}</div><div class="meta-value">{v}</div></div>'
        for k, v in kwargs.items()
    )
    return f'<div class="meta-grid">{cells}</div>'

def _section(label: str, content: str) -> str:
    return f'<div class="section"><div class="section-label">{label}</div><div class="section-body">{content}</div></div>'

def _render_html_email(notif_type: str, d: dict) -> Tuple[Optional[str], Optional[str]]:
    """
    Render (subject, html_body) for a given notification type.
    Returns (None, None) if the type has no HTML template.
    """
    sev = d.get("severity", "P4")
    ts  = d.get("timestamp", "")
    iid = d.get("incident_id", "N/A")

    if notif_type == "incident_detected":
        subject = f"🚨 [{sev}] Security Incident Detected — {iid}"
        header  = _header("🚨", "Security Incident Detected", iid, sev)
        body    = (
            _meta_grid(**{"Incident ID": iid, "Severity": sev,
                          "Threat Type": d.get("threat_type", "Unknown"),
                          "Resource": d.get("resource", "Unknown")})
            + _section("Incident Summary", d.get("summary", "").replace("\n", "<br>"))
        )

    elif notif_type == "triage_complete":
        subject  = f"📋 [{sev}] Incident Triaged — {iid}"
        conf_pct = f"{float(d.get('confidence', 0)):.0%}"
        actions_raw = d.get("actions", [])
        if isinstance(actions_raw, list):
            items = "".join(
                f'<div class="action-item"><span class="action-bullet"></span>'
                f'{a.get("action", a) if isinstance(a, dict) else a}</div>'
                for a in actions_raw
            )
        else:
            items = "".join(
                f'<div class="action-item"><span class="action-bullet"></span>'
                f'{line.strip().lstrip("- ")}</div>'
                for line in str(actions_raw).splitlines() if line.strip()
            )
        header = _header("📋", "Incident Triage Complete", iid, sev)
        body   = (
            _meta_grid(**{"Incident ID": iid, "Severity": sev,
                          "Confidence": conf_pct,
                          "Action Mode": d.get("action_mode", "Unknown")})
            + f'<div class="section"><div class="section-label">Recommended Actions</div>'
              f'<div class="actions-list">{items}</div></div>'
            + _section("Reasoning", d.get("reasoning_summary", "").replace("\n", "<br>"))
        )

    elif notif_type == "action_pending":
        aid = d.get("action_id", "N/A")

        # Robustly extract action_type
        action_type = d.get("action_type")
        if not action_type and "actions" in d and isinstance(d["actions"], list) and d["actions"]:
            first = d["actions"][0]
            action_type = first.get("action", "Unknown") if isinstance(first, dict) else "Unknown"
        action_type = action_type or "Unknown"

        # Robustly extract action_details
        action_details = d.get("action_details", "")
        if not action_details and "actions" in d and isinstance(d["actions"], list):
            lines = []
            for act in d["actions"]:
                if isinstance(act, dict):
                    lines.append(f"- {act.get('action', 'Unknown')}: {act.get('description', '')}")
                else:
                    lines.append(f"- {act}")
            action_details = "\n".join(lines)
        if not action_details:
            action_details = str(d.get("params", "No details available"))

        subject = f"⏳ [{sev}] Action Approval Required — {iid} [{aid}]"
        approval_html = f"""
        <div class="approval-box">
          <div class="approval-title">⚡ Reply to this email to approve or reject</div>
          <div class="approval-row">
            <div class="cmd-block">
              <div class="cmd-label approve">✓ Approve</div>
              <div class="cmd-text">APPROVE {aid}</div>
            </div>
            <div class="cmd-block">
              <div class="cmd-label reject">✗ Reject</div>
              <div class="cmd-text">REJECT {aid}</div>
            </div>
          </div>
        </div>"""
        header = _header("⏳", "Action Approval Required", f"{iid}  ·  {aid}", sev)
        body   = (
            _meta_grid(**{"Incident ID": iid, "Action ID": aid,
                          "Action Type": action_type, "Severity": sev})
            + approval_html
            + _section("Action Details", action_details.replace("\n", "<br>"))
        )

    elif notif_type == "action_executed":
        subject = f"✅ Action Executed — {iid}"
        header  = _header("✅", "Containment Action Executed", iid, sev)
        body    = (
            _meta_grid(**{"Incident ID": iid, "Action": d.get("action_type", "Unknown")})
            + f'<div class="status-banner success"><span class="status-icon">✓</span>'
              f'{d.get("status", "Success")}</div>'
            + _section("Execution Result", str(d.get("result", "")).replace("\n", "<br>"))
        )

    elif notif_type == "action_failed":
        subject = f"❌ Action Failed — {iid}"
        header  = _header("❌", "Containment Action Failed", iid, sev)
        body    = (
            _meta_grid(**{"Incident ID": iid, "Action ID": d.get("action_id", "N/A"),
                          "Action Type": d.get("action_type", "Unknown"), "Severity": sev})
            + '<div class="status-banner error"><span class="status-icon">✗</span>'
              'Action execution failed — manual intervention needed</div>'
            + _section("Error Details", str(d.get("error", "")).replace("\n", "<br>"))
            + _section("Summary", str(d.get("summary", "")).replace("\n", "<br>"))
        )

    elif notif_type == "incident_resolved":
        subject    = f"✅ Incident Resolved — {iid}"
        header     = _header("✅", "Incident Resolved", iid, "P4")
        stat_strip = f"""
        <div class="stat-strip">
          <div class="stat-cell">
            <div class="stat-num">{d.get("actions_count", 0)}</div>
            <div class="stat-lbl">Actions Taken</div>
          </div>
          <div class="stat-cell">
            <div class="stat-num">{d.get("duration", "N/A")}</div>
            <div class="stat-lbl">Total Duration</div>
          </div>
        </div>"""
        body = (
            _meta_grid(**{"Incident ID": iid, "Status": "Resolved ✓"})
            + stat_strip
            + _section("Resolution Summary", str(d.get("summary", "")).replace("\n", "<br>"))
        )

    elif notif_type == "containment_retries_exhausted":
        subject = f"🚨 CRITICAL: Containment Failed After {d.get('max_retries', '?')} Attempts — {iid}"
        header  = _header("🚨", "Containment Failure", "HUMAN INTERVENTION REQUIRED", "P1")
        body    = (
            _meta_grid(**{"Incident ID": iid, "Resource": d.get("resource", "Unknown"),
                          "Retries": d.get("max_retries", "N/A"), "Time": ts})
            + '<div class="status-banner warning"><span class="status-icon">⚠</span>'
              'Automated containment exhausted — manual action required</div>'
            + _section("Situation Summary", str(d.get("summary", "")).replace("\n", "<br>"))
        )

    else:
        return None, None

    return subject, _html_wrap(header, body, ts)


# ---------------------------------------------------------------------------
# EmailNotifier — outbound SMTP
# ---------------------------------------------------------------------------
class EmailNotifier:
    """Send notifications via SMTP."""

    def __init__(self):
        self.configured = all(
            [config.smtp_host, config.smtp_user, config.smtp_password, config.alert_email]
        )
        if not self.configured:
            log.warning("Email notifications not configured - missing SMTP settings")

    async def send(
        self,
        to: str,
        subject: str,
        html_body: str = "",
        plain_body: str = "",
    ) -> bool:
        """
        Send an email. Automatically selects:
          - multipart/alternative  when both bodies are provided  (best)
          - HTML-only              when only html_body is provided
          - plain-only             when only plain_body is provided
        """
        if not self.configured:
            log.debug("Email skipped - not configured")
            return False

        if not html_body and not plain_body:
            log.warning("Email skipped - no body content", subject=subject)
            return False

        try:
            if html_body and plain_body:
                message = MIMEMultipart("alternative")
                message["From"]    = config.smtp_user
                message["To"]      = to
                message["Subject"] = subject
                message.attach(MIMEText(plain_body, "plain"))
                message.attach(MIMEText(html_body,  "html"))
            elif html_body:
                message = MIMEMultipart("alternative")
                message["From"]    = config.smtp_user
                message["To"]      = to
                message["Subject"] = subject
                message.attach(MIMEText(html_body, "html"))
            else:
                message = MIMEMultipart()
                message["From"]    = config.smtp_user
                message["To"]      = to
                message["Subject"] = subject
                message.attach(MIMEText(plain_body, "plain"))

            await aiosmtplib.send(
                message,
                hostname=config.smtp_host,
                port=config.smtp_port,
                username=config.smtp_user,
                password=config.smtp_password,
                start_tls=True,
            )
            log.info("Email sent", to=to, subject=subject[:80])
            return True
        except Exception as e:
            log.error("Failed to send email", error=str(e))
            return False


# ---------------------------------------------------------------------------
# EmailReceiver — inbound IMAP polling with duplicate prevention
# ---------------------------------------------------------------------------
class EmailReceiver:
    """
    Poll IMAP inbox for approval replies. Uses Redis to avoid duplicate
    processing if aioredis is installed; otherwise falls back to an
    in-memory set (duplicates may be processed after a restart).
    """

    _DECISION_RE = re.compile(r"\b(APPROVE|REJECT)\s+([A-Za-z0-9_\-]+)\b", re.IGNORECASE)
    _PROCESSED_SET_KEY = "processed_email_uids"

    def __init__(self):
        self.configured = all(
            [config.imap_host, config.imap_user, config.imap_password]
        )
        if not self.configured:
            log.warning("IMAP polling not configured - missing IMAP settings")

        self.client: Optional[aioimaplib.IMAP4_SSL] = None
        self.poll_interval: int = 30
        self.redis = None
        self._in_memory_processed = set()
        self._redis_available = False
        self._redis_initialised = False

    async def _ensure_redis(self):
        if self._redis_initialised:
            return
        try:
            import aioredis
            self._redis_available = True
        except ImportError:
            self._redis_available = False
            log.warning("aioredis not installed, using in-memory fallback for processed UIDs")
            self._redis_initialised = True
            return

        try:
            if hasattr(config, 'redis_url') and config.redis_url:
                self.redis = await aioredis.from_url(config.redis_url, decode_responses=True)
            elif hasattr(config, 'redis_host') and hasattr(config, 'redis_port'):
                self.redis = await aioredis.from_url(
                    f"redis://{config.redis_host}:{config.redis_port}",
                    decode_responses=True,
                    password=getattr(config, 'redis_password', None),
                )
            else:
                log.warning("No Redis configuration found, using in-memory fallback")
                self._redis_available = False
                self._redis_initialised = True
                return
            await self.redis.ping()
            log.info("Connected to Redis for processed UIDs")
        except Exception as e:
            log.warning("Redis connection failed, using in-memory fallback", error=str(e))
            self.redis = None
            self._redis_available = False

        self._redis_initialised = True

    async def connect(self) -> bool:
        if not self.configured:
            return False
        try:
            self.client = aioimaplib.IMAP4_SSL(
                host=config.imap_host, port=config.imap_port or 993
            )
            await self.client.wait_hello_from_server()
            await self.client.login(config.imap_user, config.imap_password)
            await self.client.select("INBOX")
            log.info("IMAP connected and INBOX selected")
            return True
        except Exception as e:
            log.error("IMAP connection failed", error=str(e))
            self.client = None
            return False

    async def disconnect(self):
        if self.client:
            try:
                await self.client.logout()
            except Exception:
                pass
            self.client = None

    async def poll_once(self) -> List[Tuple[str, bool, str]]:
        if not self.client:
            if not await self.connect():
                return []

        await self._ensure_redis()
        await self.client.select("INBOX")
        seq_nums = await self._get_recent_seq_nums(days=1)
        log.info("IMAP poll: scanning recent messages", count=len(seq_nums))

        if not seq_nums:
            return []

        results = []
        for seq in seq_nums:
            try:
                uid = await self._fetch_uid(seq)
                if uid:
                    if self.redis:
                        if await self.redis.sismember(self._PROCESSED_SET_KEY, uid):
                            log.debug("Skipping already processed email (Redis)", seq=seq, uid=uid)
                            continue
                    elif uid in self._in_memory_processed:
                        log.debug("Skipping already processed email (in-memory)", seq=seq, uid=uid)
                        continue

                typ, data = await self.client.fetch(seq, "(RFC822)")
                if typ != "OK" or not data:
                    continue

                raw_bytes = next(
                    (item for item in data if isinstance(item, (bytes, bytearray)) and len(item) > 100),
                    None,
                )
                if not raw_bytes:
                    continue

                msg     = email.message_from_bytes(raw_bytes)
                subject = msg.get("Subject", "")
                body    = self._extract_plain_body(msg)
                sender  = msg.get("From", "unknown")

                is_reply = (
                    "re:" in subject.lower()[:10]
                    or msg.get("In-Reply-To") is not None
                    or msg.get("References") is not None
                )
                if not is_reply:
                    continue

                decision = self._parse_decision(subject + "\n" + body)
                if decision:
                    action_id, approved = decision
                    results.append((action_id, approved, sender))
                    log.info("✅ Parsed approval decision from email",
                             seq=seq, action_id=action_id, approved=approved, sender=sender)

                    if uid:
                        if self.redis:
                            await self.redis.sadd(self._PROCESSED_SET_KEY, uid)
                            await self.redis.expire(self._PROCESSED_SET_KEY, 60 * 60 * 24 * 7)
                        else:
                            self._in_memory_processed.add(uid)

                    await self.client.store(seq, '+FLAGS', '\\Seen')

            except Exception as e:
                log.error("Error processing message", seq=seq, error=str(e))
                continue

        return results

    async def _fetch_uid(self, seq: str) -> Optional[str]:
        try:
            typ, data = await self.client.fetch(seq, "(UID)")
            if typ == "OK" and data:
                match = re.search(rb'UID (\d+)', data[0] if isinstance(data[0], bytes) else b'')
                if match:
                    return match.group(1).decode()
        except Exception as e:
            log.debug("Failed to fetch UID", seq=seq, error=str(e))
        return None

    async def _get_recent_seq_nums(self, days: int = 1) -> List[str]:
        try:
            since_date = (datetime.utcnow() - timedelta(days=days)).strftime("%d-%b-%Y")
            typ, data  = await self.client.search(f"SINCE {since_date}")
            if typ != "OK" or not data or not data[0]:
                return []
            raw = data[0]
            if isinstance(raw, bytes):
                raw = raw.decode()
            return raw.split()[-30:]
        except Exception as e:
            log.error("_get_recent_seq_nums failed", error=str(e))
            try:
                typ, data = await self.client.search("ALL")
                if typ == "OK" and data and data[0]:
                    raw = data[0]
                    if isinstance(raw, bytes):
                        raw = raw.decode()
                    all_seqs = raw.split()
                    return all_seqs[-10:] if all_seqs else []
            except Exception as e2:
                log.error("Fallback ALL search failed", error=str(e2))
            return []

    def _extract_plain_body(self, msg: email.message.Message) -> str:
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        return payload.decode(errors="ignore")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                return payload.decode(errors="ignore")
        return ""

    def _parse_decision(self, text: str) -> Optional[Tuple[str, bool]]:
        match = self._DECISION_RE.search(text)
        if match:
            command, action_id = match.group(1), match.group(2)
            return action_id, command.upper() == "APPROVE"
        return None


# ---------------------------------------------------------------------------
# TerminalNotifier — always available fallback
# ---------------------------------------------------------------------------
class TerminalNotifier:
    """Send notifications to terminal (always available)."""

    COLORS = {
        "P1": "\033[91m",
        "P2": "\033[93m",
        "P3": "\033[94m",
        "P4": "\033[92m",
        "reset": "\033[0m",
        "bold": "\033[1m",
    }

    def notify(self, notification: Dict[str, Any]):
        severity   = notification.get("severity", "P4")
        color      = self.COLORS.get(severity, "")
        reset      = self.COLORS["reset"]
        bold       = self.COLORS["bold"]
        notif_type = notification.get("type", "unknown")

        print(f"\n{color}{bold}{'='*60}{reset}")
        print(f"{color}{bold}[{severity}] {notif_type.upper().replace('_', ' ')}{reset}")
        print(f"{color}{'='*60}{reset}")
        for key, value in notification.items():
            if key not in ("type", "severity"):
                print(f"  {key}: {value}")
        print(f"{color}{'='*60}{reset}\n")


# ---------------------------------------------------------------------------
# CommunicationAgent — orchestrates outbound + inbound
# ---------------------------------------------------------------------------
class CommunicationAgent:
    """Main communication agent handling all notifications and approval replies."""

    def __init__(self):
        self.email_sender   = EmailNotifier()
        self.email_receiver = EmailReceiver()
        self.terminal       = TerminalNotifier()
        self.running        = False
        self._poll_task: Optional[asyncio.Task] = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    async def start(self):
        self.running = True
        log.info("Communication Agent started")
        asyncio.create_task(self._notification_loop(), name="notif_loop")

        if self.email_receiver.configured:
            self._poll_task = asyncio.create_task(
                self._email_polling_loop(), name="imap_poll"
            )
            log.info("Email approval polling started",
                     poll_interval_seconds=self.email_receiver.poll_interval)
        else:
            log.info("Email approval polling disabled (missing IMAP config)")

    async def stop(self):
        self.running = False
        if self._poll_task:
            self._poll_task.cancel()
            try:
                await self._poll_task
            except asyncio.CancelledError:
                pass
        await self.email_receiver.disconnect()
        log.info("Communication Agent stopped")

    # ------------------------------------------------------------------
    # Notification loop
    # ------------------------------------------------------------------
    async def _notification_loop(self):
        while self.running:
            try:
                if queue is None:
                    log.error("Queue object is None – check core export")
                    await asyncio.sleep(5)
                    continue
                notification = await queue.pop("notification", timeout=5)
                if notification:
                    await self._process_notification(notification)
            except NameError:
                log.error("Queue name not defined – import failed")
                await asyncio.sleep(5)
            except Exception as e:
                log.error("Error processing notification", error=str(e))
                await asyncio.sleep(1)

    # ------------------------------------------------------------------
    # IMAP polling loop
    # ------------------------------------------------------------------
    async def _email_polling_loop(self):
        while self.running:
            try:
                decisions = await self.email_receiver.poll_once()
                for action_id, approved, sender in decisions:
                    await self._process_email_decision(action_id, approved, sender)
                await asyncio.sleep(self.email_receiver.poll_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                log.error("Email polling loop error", error=str(e))
                await asyncio.sleep(self.email_receiver.poll_interval)

    async def _process_email_decision(self, action_id: str, approved: bool, sender: str):
        decision_payload = {
            "approved":    approved,
            "approved_by": f"email:{sender}",
            "approved_at": datetime.utcnow().isoformat(),
        }
        if not approved:
            decision_payload["rejected_by"] = decision_payload.pop("approved_by")
            decision_payload["rejected_at"] = decision_payload.pop("approved_at")
            decision_payload["reason"]       = "Rejected via email reply"

        await queue.push(f"approval:{action_id}", decision_payload)

        verb = "APPROVED" if approved else "REJECTED"
        log.info(f"Action {verb} via email reply", action_id=action_id, sender=sender)

        await queue.push("notification", {
            "type":        "action_approved" if approved else "action_rejected",
            "severity":    "P3",
            "action_id":   action_id,
            "approved_by": sender,
            "summary":     f"Action {action_id} {verb.lower()} by {sender} via email",
        })

    # ------------------------------------------------------------------
    # Process outbound notifications  ← THE FIXED METHOD
    # ------------------------------------------------------------------
    async def _process_notification(self, notification: Dict[str, Any]):
        """
        Process and dispatch a notification through all channels.

        EMAIL STRATEGY (fixed):
        ───────────────────────
        1. Try HTML template  → html_body, html_subject
        2. Try plain template → plain_body, plain_subject
        3. Send if EITHER produced content — no "channels" gate.
           Both available  → multipart/alternative (HTML + readable fallback)
           HTML only       → HTML email
           Plain only      → plain-text email
        4. If neither template exists for this type → skip email silently
           (e.g. internal-only types: action_approved, action_rejected,
            actions_auto_approved, trust_level_changed)

        This matches the reliability of the original TEMPLATES-dict approach
        while keeping rich HTML for supported types.
        """
        notif_type = notification.get("type", "unknown")
        timestamp  = datetime.utcnow().isoformat()
        notification["timestamp"] = timestamp

        # Always echo to terminal
        self.terminal.notify(notification)

        email_sent = False
        subject    = None

        if config.alert_email:
            html_body  = None
            plain_body = None

            # Step 1: Try HTML template
            try:
                html_subject, html_body = _render_html_email(notif_type, notification)
                if html_subject:
                    subject = html_subject
            except Exception as e:
                log.error("HTML rendering failed", error=str(e), type=notif_type)
                html_body = None

            # Step 2: Try plain-text template (always — used as fallback body too)
            plain_tmpl = PLAIN_TEMPLATES.get(notif_type)
            if plain_tmpl:
                try:
                    plain_subject, plain_body = _render_plain_template(plain_tmpl, notification)
                    if not subject:
                        subject = plain_subject
                except Exception as e:
                    log.error("Plain template rendering failed", error=str(e), type=notif_type)
                    plain_body = None

            # Step 3: Send if we have anything to send
            if subject and (html_body or plain_body):
                email_sent = await self.email_sender.send(
                    config.alert_email,
                    subject,
                    html_body  or "",
                    plain_body or "",
                )
                log.info("Email dispatched",
                         type=notif_type,
                         subject=subject[:80],
                         has_html=bool(html_body),
                         has_plain=bool(plain_body),
                         sent=email_sent)
            else:
                log.debug("No email template for notification type — skipping email",
                          type=notif_type)

            if subject and (email_sent or html_body or plain_body):
                await save_notification({
                    "incident_id": notification.get("incident_id"),
                    "channel":     "email",
                    "message":     subject,
                    "status":      "sent" if email_sent else "failed",
                    "sent_at":     timestamp if email_sent else None,
                })

        # Always save terminal record
        await save_notification({
            "incident_id": notification.get("incident_id"),
            "channel":     "terminal",
            "message":     f"[{notif_type}] {notification.get('summary', '')}",
            "status":      "sent",
            "sent_at":     timestamp,
        })

        # Publish real-time update
        await queue.publish("live_updates", notification)

    # ------------------------------------------------------------------
    # Convenience: bypass queue for urgent sends
    # ------------------------------------------------------------------
    async def send_immediate(self, notification: Dict[str, Any]):
        """Send notification immediately, bypassing the queue."""
        await self._process_notification(notification)


# Agent instance
communication_agent = CommunicationAgent()