"""
Triage Agent - Pure Analysis Only

Analyzes the incident: severity, confidence, false positive detection, reasoning chain.
Does NOT recommend actions - that is the Decision Agent's job.
Does NOT decide auto/approval - that is the Decision Agent's job.

Flow: triage queue → context → LLM analyze → save → push incident_id to decision queue
"""

import asyncio
from datetime import datetime
from typing import Dict, Any, List
import structlog

from core import (
    queue, llm_client, save_enriched_incident, save_reasoning_chain,
    update_incident, EnrichedIncident, Severity,
    ActionMode, ReasoningStep, IncidentStatus
)
from agents.context import context_agent

log = structlog.get_logger()


def _convert_to_reasoning_step(step_data: Any) -> ReasoningStep:
    """Convert various reasoning step formats to ReasoningStep model."""
    if isinstance(step_data, ReasoningStep):
        return step_data

    if isinstance(step_data, dict):
        if "type" in step_data and "content" in step_data:
            return ReasoningStep(**step_data)

        if "thought" in step_data or "evidence" in step_data or "conclusion" in step_data:
            parts = []
            if "thought" in step_data:
                parts.append(f"Thought: {step_data['thought']}")
            if "evidence" in step_data:
                parts.append(f"Evidence: {step_data['evidence']}")
            if "conclusion" in step_data:
                parts.append(f"Conclusion: {step_data['conclusion']}")
            step_type = "conclusion" if "conclusion" in step_data else "analysis"
            return ReasoningStep(
                type=step_type,
                content=" | ".join(parts) if parts else str(step_data),
                confidence=step_data.get("confidence")
            )

        return ReasoningStep(type="observation", content=str(step_data))

    return ReasoningStep(type="observation", content=str(step_data))


class TriageAgent:
    """
    Triage Agent - analysis only.

    Responsibilities:
    - Assemble incident context via Context Agent (MITRE, criticality, forensics)
    - Run LLM analysis: severity, confidence, false positive detection, reasoning chain
    - Save enriched incident + reasoning chain to DB
    - Hand off to Decision Agent with just incident_id + severity + confidence

    Does NOT recommend containment actions - Decision Agent does that.
    Does NOT decide auto vs approval - Decision Agent does that.
    """

    def __init__(self):
        self.running = False

    async def start(self):
        self.running = True
        log.info("Triage Agent started")
        await self._triage_loop()

    async def stop(self):
        self.running = False
        log.info("Triage Agent stopped")

    async def _triage_loop(self):
        while self.running:
            try:
                incident_data = await queue.pop("triage", timeout=5)
                if incident_data:
                    await self._process_incident(incident_data)
            except Exception as e:
                log.error("Error in triage loop", error=str(e), exc_info=True)
                await asyncio.sleep(1)

    async def _process_incident(self, incident: Dict[str, Any]):
        incident_id = incident.get("id")
        threat_type = incident.get("type")

        log.info("Triaging incident", incident_id=incident_id, threat_type=threat_type)

        try:
            # 1. Assemble context (MITRE mapping, asset criticality, forensics)
            base_context = await context_agent.assemble_context(incident_id)

            # 2. Build analysis context for LLM
            #    Triage LLM focuses on: is this real? how severe? how confident?
            #    It does NOT need to know available actions - that is Decision Agent's concern
            analysis_context = {
                "mitre_mapping": base_context.get("mitre_mapping", {}),
                "asset_criticality": base_context.get("asset_criticality", {}),
                "has_live_forensics": base_context.get("has_live_forensics", False),
                "forensic_snapshot": base_context.get("forensic_snapshot", {}),
            }

            analysis = await llm_client.analyze_incident(incident, analysis_context)

            log.debug("LLM triage analysis complete",
                      incident_id=incident_id,
                      severity=analysis.get("severity"),
                      confidence=analysis.get("confidence"),
                      is_false_positive=analysis.get("is_false_positive"))

            # 3. False positive check — stop pipeline here if false positive
            if analysis.get("is_false_positive"):
                await update_incident(incident_id, {"status": IncidentStatus.FALSE_POSITIVE.value})
                await queue.push("notification", {
                    "type": "false_positive",
                    "incident_id": incident_id,
                    "severity": "P4",
                    "summary": "Incident marked as false positive by triage",
                    "reasoning": analysis.get("summary", "LLM determined this is not a real threat"),
                })
                log.info("Incident marked as false positive", incident_id=incident_id)
                return

            # 4. Parse severity and confidence
            severity = Severity(analysis.get("severity", "P3"))
            confidence = min(max(analysis.get("confidence", 0.5), 0.0), 1.0)

            # 5. Build reasoning chain from LLM output
            reasoning_chain = []
            for step in analysis.get("reasoning_chain", []):
                try:
                    reasoning_chain.append(_convert_to_reasoning_step(step))
                except Exception as e:
                    log.warning("Failed to convert reasoning step", step=step, error=str(e))
                    reasoning_chain.append(ReasoningStep(type="observation", content=str(step)))

            # 6. Save enriched incident to DB
            #    recommended_actions is intentionally empty here —
            #    Decision Agent will determine these using full context + ActionRegistry
            enriched = EnrichedIncident(
                incident_id=incident_id,
                severity=severity,
                confidence=confidence,
                recommended_actions=[],
                action_mode=ActionMode.APPROVAL_REQUIRED,  # placeholder, Decision Agent overrides
                reasoning_chain=reasoning_chain,
                context={
                    "mitre_mapping": base_context.get("mitre_mapping", {}),
                    "asset_criticality": base_context.get("asset_criticality", {}),
                    "llm_summary": analysis.get("summary", ""),
                    "triaged_at": datetime.utcnow().isoformat(),
                },
            )

            await save_enriched_incident(enriched.model_dump(mode='json'))
            await save_reasoning_chain(incident_id, [r.model_dump() for r in reasoning_chain])
            await update_incident(incident_id, {
                "status": IncidentStatus.TRIAGED.value,
                "severity": severity.value,
            })

            # 7. Annotate context cache with triage results
            context_agent.update_context(incident_id, "triage", {
                "severity": severity.value,
                "confidence": confidence,
                "llm_summary": analysis.get("summary", ""),
            })

            # 8. Hand off to Decision Agent
            #    Only pass what triage knows: incident_id, severity, confidence
            #    Decision Agent fetches full context itself via context_agent
            await queue.push("decision", {
                "incident_id": incident_id,
                "severity": severity.value,
                "confidence": confidence,
                "retry_number": 0,
            })

            await queue.push("notification", {
                "type": "triage_complete",
                "incident_id": incident_id,
                "severity": severity.value,
                "confidence": confidence,
                "action_mode": "pending_decision",
                "reasoning_summary": analysis.get("summary", "Analysis complete"),
            })

            log.info("Triage complete, handed to Decision Agent",
                     incident_id=incident_id,
                     severity=severity.value,
                     confidence=confidence)

        except Exception as e:
            log.error("Triage failed", incident_id=incident_id, error=str(e), exc_info=True)
            await queue.push("notification", {
                "type": "triage_error",
                "incident_id": incident_id,
                "severity": "P2",
                "summary": f"Triage failed: {str(e)}",
            })


# Agent instance
triage_agent = TriageAgent()