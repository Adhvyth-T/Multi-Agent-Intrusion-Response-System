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
                # Try gemini-2.5-flash instead (more stable)
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
                
                # Log the actual error details
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
        
        # Parse JSON from response
        import json
        try:
            # Try to extract JSON from response
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            log.error("Failed to parse LLM response as JSON", response=response[:200])
        
        # Return default analysis on parse failure
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

        # Parse JSON from response
        import json
        try:
            start = response.find('{')
            end = response.rfind('}') + 1
            if start != -1 and end > start:
                return json.loads(response[start:end])
        except json.JSONDecodeError:
            log.error("Failed to parse root cause analysis", response=response[:200])

        # Fallback
        return {
            "summary": f"Root cause analysis for incident {incident.get('incident_id', 'unknown')}",
            "attack_vector": "Analysis pending",
            "root_cause": "Investigation in progress",
            "confidence": 0.7,
            "recommendations": ["Review forensic evidence", "Monitor for similar attacks"]
        }

# Singleton
llm_client = LLMClient()