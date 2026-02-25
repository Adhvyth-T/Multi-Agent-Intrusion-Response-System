import httpx
from typing import Optional, Dict, Any
from config import config
import structlog
from tenacity import retry, stop_after_attempt, wait_exponential

log = structlog.get_logger()

class LLMClient:
    """LLM client with Gemini primary and OpenRouter fallback."""
    
    def __init__(self):
        self.gemini_configured = bool(config.gemini_api_key)
        self.openrouter_configured = bool(config.openrouter_api_key)
        self.gemini_api_key = config.gemini_api_key
        
        if self.gemini_configured:
            log.info("Gemini API configured")
        
        if self.openrouter_configured:
            log.info("OpenRouter API configured as fallback")
    
    async def generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate response using Gemini with OpenRouter fallback."""
        
        # Try Gemini first
        if self.gemini_configured:
            try:
                return await self._gemini_generate(prompt, system_prompt)
            except Exception as e:
                log.warning("Gemini failed, trying OpenRouter", 
                           error=str(e), 
                           error_type=type(e).__name__)
        
        # Fallback to OpenRouter
        if self.openrouter_configured:
            try:
                return await self._openrouter_generate(prompt, system_prompt)
            except Exception as e:
                log.error("OpenRouter also failed", error=str(e))
                raise
        
        raise RuntimeError("No LLM API configured or all failed")
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _gemini_generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using Gemini API (REST)."""
        full_prompt = prompt
        if system_prompt:
            full_prompt = f"{system_prompt}\n\n{prompt}"
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={self.gemini_api_key}"
                
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json={
                        "contents": [{"parts": [{"text": full_prompt}]}],
                        "generationConfig": {
                            "temperature": 0.7, 
                            "maxOutputTokens": 7000
                        }
                    }
                )
                
                if response.status_code != 200:
                    error_body = response.text
                    log.error("Gemini API error", 
                             status_code=response.status_code,
                             error=error_body[:500])
                
                response.raise_for_status()
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
                
        except httpx.HTTPStatusError as e:
            log.error("Gemini HTTP error", 
                     status=e.response.status_code,
                     error=e.response.text[:500])
            raise
        except Exception as e:
            log.error("Gemini unexpected error", error=str(e))
            raise
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
    async def _openrouter_generate(self, prompt: str, system_prompt: Optional[str] = None) -> str:
        """Generate using OpenRouter API."""
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {config.openrouter_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": config.openrouter_model,
                    "messages": messages,
                }
            )
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
    
    async def analyze_incident(self, incident: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze incident and return structured analysis."""
        
        system_prompt = """You are a security incident response AI analyst. Analyze the incident and provide:
1. Severity assessment (P1=Critical, P2=High, P3=Medium, P4=Low)
2. Confidence score (0.0-1.0)
3. Recommended containment actions
4. Reasoning chain explaining your analysis

Respond in this exact JSON format:
{
    "severity": "P1|P2|P3|P4",
    "confidence": 0.0-1.0,
    "is_false_positive": true|false,
    "recommended_actions": [
        {"action": "action_name", "params": {}, "priority": 1}
    ],
    "reasoning_chain": [
        {"type": "observation", "content": "...", "confidence": 0.9},
        {"type": "analysis", "content": "...", "confidence": 0.85},
        {"type": "conclusion", "content": "...", "confidence": 0.9}
    ],
    "summary": "Brief summary of the threat"
}"""
        
        prompt = f"""Analyze this security incident:

INCIDENT:
- Type: {incident.get('type')}
- Source: {incident.get('source')}
- Resource: {incident.get('resource')}
- Namespace: {incident.get('namespace')}
- Raw Event: {incident.get('raw_event')}

CONTEXT:
{context}

Provide your analysis in the specified JSON format."""
        
        response = await self.generate(prompt, system_prompt)
        
        import json
        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            log.error("Failed to parse LLM response as JSON", response=response[:200])
        
        return {
            "severity": "P3",
            "confidence": 0.5,
            "is_false_positive": False,
            "recommended_actions": [],
            "reasoning_chain": [
                {"type": "error", "content": "Failed to parse LLM response", "confidence": 0.5}
            ],
            "summary": "Analysis incomplete due to parsing error"
        }

    async def analyze_incident_root_cause(self, incident: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized root cause analysis for Investigation Agent."""

        system_prompt = """You are a forensic security analyst performing root cause analysis. Given comprehensive incident data and forensic evidence, determine:

1. Root cause and attack vector
2. How the attack succeeded
3. What should be done to prevent recurrence
4. Assessment of attacker sophistication

Respond in this exact JSON format:
{
    "summary": "Concise description of what happened",
    "attack_vector": "How the attack was executed",
    "root_cause": "Underlying vulnerability or weakness",
    "confidence": 0.0-1.0,
    "attacker_sophistication": "Low|Medium|High",
    "impact_assessment": "Description of impact",
    "recommendations": [
        "Specific preventive measures",
        "Security improvements needed"
    ]
}"""

        prompt = f"""Perform root cause analysis on this security incident:

INCIDENT DETAILS:
- ID: {incident.get('incident_id')}
- Type: {incident.get('type')}
- Resource: {incident.get('resource')}

FORENSIC ANALYSIS CONTEXT:
{context}

Provide detailed root cause analysis in the specified JSON format."""

        response = await self.generate(prompt, system_prompt)

        import json
        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            log.error("Failed to parse root cause analysis", response=response[:200])

        return {
            "summary": f"Root cause analysis for incident {incident.get('incident_id', 'unknown')}",
            "attack_vector": "Analysis pending",
            "root_cause": "Investigation in progress",
            "confidence": 0.7,
            "recommendations": ["Review forensic evidence", "Monitor for similar attacks"]
        }

    async def select_containment_actions(
        self,
        incident: Dict[str, Any],
        mitre_mapping: Dict[str, Any],
        asset_criticality: Dict[str, Any],
        forensic_snapshot: Dict[str, Any],
        triage_summary: str,
        available_actions: Dict[str, Any],
        pipeline_history: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Select the best containment actions for an incident from the registered executors.
        Called by Decision Agent on first call (retry_number=0).

        pipeline_history (optional): structured context from all prior pipeline stages.
        {
            "retry_number": 0,
            "triage":      {"severity", "confidence", "summary"},
            "decision":    {"action_mode", "actions_queued", "resource"},
            "containment": {"actions_taken": [{"action_type", "success", "message"}]},
            "validation":  {"last_failure_phase", "last_failure_message", "last_failed_action"}
        }

        Returns:
        {
            "actions": [{"action": "name", "params": {}, "priority": 1, "reason": "..."}],
            "reasoning": "overall strategy"
        }
        """
        import json as _json

        system_prompt = """You are a containment strategy expert for an autonomous incident response system.
Given a security incident and a list of available containment executors, select the best actions to contain the threat.

Rules:
- Only recommend actions from the provided available_actions list. Never invent action names.
- Prefer non-destructive actions unless the threat severity demands immediate removal.
- For P1/P2 incidents, prioritize stopping the threat over preserving the environment.
- For P3/P4, prefer reversible actions that preserve forensic evidence.
- Return 1-3 actions maximum, ordered by priority (1 = highest).
- params should be empty {} unless you have specific values to pass.

Respond ONLY in this exact JSON format with no extra text:
{
    "actions": [
        {"action": "action_name", "params": {}, "priority": 1, "reason": "why this action"},
        {"action": "action_name", "params": {}, "priority": 2, "reason": "why this action"}
    ],
    "reasoning": "overall strategy explanation"
}"""

        # Build pipeline history section
        history_section = ""
        if pipeline_history:
            triage = pipeline_history.get("triage", {})
            decision = pipeline_history.get("decision", {})
            containment = pipeline_history.get("containment", {})
            validation = pipeline_history.get("validation", {})

            history_section = f"""
PIPELINE HISTORY:
- Triage severity: {triage.get("severity", "unknown")}, confidence: {triage.get("confidence", "unknown")}
- Triage analysis: {triage.get("summary", "not available")}
- Decision mode: {decision.get("action_mode", "unknown")}, resource: {decision.get("resource", "unknown")}
"""
            actions_taken = containment.get("actions_taken", [])
            if actions_taken:
                history_section += "- Prior containment actions:\n"
                for a in actions_taken:
                    status = "✓ succeeded" if a.get("success") else "✗ failed"
                    history_section += f"  • {a.get('action_type')}: {status} — {a.get('message', '')}\n"

            if validation.get("last_failure_message"):
                history_section += f"- Validation failure ({validation.get('last_failure_phase')}): {validation.get('last_failure_message')}\n"

        prompt = f"""Select containment actions for this incident:

INCIDENT:
- Type: {incident.get('type')}
- Severity: {incident.get('severity')}
- Resource: {incident.get('resource')}
- Namespace: {incident.get('namespace')}

THREAT INTELLIGENCE:
- MITRE: {mitre_mapping.get('technique', 'Unknown')} ({mitre_mapping.get('tactic', 'Unknown')})
- Asset Criticality: {asset_criticality.get('level', 'medium')} (score: {asset_criticality.get('score', 5)})
- Criticality Reasons: {', '.join(asset_criticality.get('reasons', [])) or 'none'}

TRIAGE ANALYSIS:
{triage_summary or 'No triage summary available'}

LIVE FORENSICS AVAILABLE: {bool(forensic_snapshot)}
{history_section}
AVAILABLE CONTAINMENT ACTIONS:
{_json.dumps(available_actions, indent=2)}

Select the best 1-3 actions to contain this threat."""

        response = await self.generate(prompt, system_prompt)

        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return _json.loads(response[start:end])
        except _json.JSONDecodeError:
            log.error("Failed to parse action selection response", response=response[:200])

        return {"actions": [], "reasoning": "LLM response parse failed"}

    async def analyze_containment_failure(
        self,
        incident: Dict[str, Any],
        failed_attempts: list,
        available_actions: list,
        pipeline_history: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Analyze why containment failed and recommend next action.
        Called by Decision Agent on retry (retry_number > 0).

        failed_attempts: all prior execution + validation outcomes. Each entry has:
          - action_type, success, message, error, status, source  (from containment execution)
          - OR: action_type, phase, message, source="ivam_validation" (from validation failure)
          - OR: action_type, failure_summary, source="db_retry_history"

        pipeline_history (optional): full structured context from all pipeline stages.

        Key insight: some failures mean containment ALREADY SUCCEEDED.
        e.g. Phase 2 "Cannot verify - container inspect failed" after a successful
        network_isolate means the container was removed = threat is contained.

        Returns:
        {
            "containment_already_succeeded": true|false,
            "reason": "what actually happened",
            "recommended_action": "action_name or null if already succeeded",
            "recommended_params": {},
            "confidence": 0.0-1.0,
            "reasoning": "explanation"
        }
        """
        import json as _json

        system_prompt = """You are a containment strategy analyst for an autonomous incident response system.
You are given all prior containment and validation outcomes, plus the full pipeline history.

Your job:
1. Determine if the failures indicate containment ALREADY SUCCEEDED
2. If not, recommend what to try next from the available actions

Signs that containment already succeeded:
- A containment action (network_isolate, delete_pod, pause_container) succeeded (success=true),
  AND the next validation phase failed because the container could not be inspected/found.
  This means the container was removed between execution and validation — threat is contained.
- Any error containing "not found", "no such container", "already removed", "already stopped"
  when the goal was to remove or isolate that resource.
- Validation phase2/phase3 message "Cannot verify - container inspect failed" after a successful action.

Respond ONLY in this exact JSON format with no extra text:
{
    "containment_already_succeeded": true|false,
    "reason": "what actually happened",
    "recommended_action": "action_name from available list, or null if already succeeded",
    "recommended_params": {},
    "confidence": 0.0-1.0,
    "reasoning": "full explanation of your analysis"
}"""

        # Build structured pipeline history section
        history_section = ""
        if pipeline_history:
            triage = pipeline_history.get("triage", {})
            containment = pipeline_history.get("containment", {})
            validation = pipeline_history.get("validation", {})
            retry_number = pipeline_history.get("retry_number", 0)

            history_section = f"""
PIPELINE HISTORY (retry #{retry_number}):
Triage: severity={triage.get("severity")}, confidence={triage.get("confidence")}
Analysis: {triage.get("summary", "not available")}

Containment actions executed:"""
            actions_taken = containment.get("actions_taken", [])
            if actions_taken:
                for a in actions_taken:
                    status = "✓ succeeded" if a.get("success") else "✗ failed"
                    history_section += f"\n  • {a.get('action_type')}: {status} — {a.get('message', '')}"
                    if a.get("error"):
                        history_section += f" (error: {a.get('error')})"
            else:
                history_section += "\n  (no in-memory records)"

            history_section += "\n\nValidation results:"
            all_failures = validation.get("all_failures", [])
            if all_failures:
                for f in all_failures:
                    history_section += f"\n  • Phase {f.get('phase')}, action={f.get('action')}: {f.get('message')}"
            elif validation.get("last_failure_message"):
                history_section += f"\n  • Phase {validation.get('last_failure_phase')}, action={validation.get('last_failed_action')}: {validation.get('last_failure_message')}"
            else:
                history_section += "\n  (no validation failures recorded)"

        prompt = f"""Analyze containment situation for incident type '{incident.get("type")}' on resource '{incident.get("resource")}':
{history_section}

ALL PRIOR ATTEMPTS (execution + validation outcomes):
{_json.dumps(failed_attempts, indent=2)}

AVAILABLE ACTIONS TO TRY NEXT (only suggest from this list):
{_json.dumps(available_actions, indent=2)}

Based on all the above, determine if containment already succeeded or recommend the next action."""

        response = await self.generate(prompt, system_prompt)

        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return _json.loads(response[start:end])
        except _json.JSONDecodeError:
            log.error("Failed to parse containment failure analysis", response=response[:200])

        return {
            "containment_already_succeeded": False,
            "reason": "LLM analysis failed",
            "recommended_action": None,
            "recommended_params": {},
            "confidence": 0.3,
            "reasoning": "Falling back to rule-based escalation",
        }


# Singleton
llm_client = LLMClient()