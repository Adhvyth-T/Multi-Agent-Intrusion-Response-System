# Autonomous Incident Response System

An AI-powered multi-agent system that autonomously detects, triages, contains, validates, and investigates security incidents in containerized environments — end-to-end, in under a minute.

---

## Directory Structure

```
Multi-Agent-ir-system/
├── .env.example
├── .gitignore
├── README.md
├── approve.py
├── dashboard.py
├── docker-compose.yml
├── main.py
├── requirements.txt
├── simulate.py
│
├── agents/
│   ├── __init__.py
│   ├── communication.py
│   ├── containment.py
│   ├── context.py
│   ├── decision_agent.py
│   ├── detection.py
│   ├── investigation.py
│   ├── triage.py
│   ├── trust_engine.py
│   └── validation_service.py
│
├── attack_simulator/
│   ├── __init__.py
│   ├── real_attacks.py
│   └── simulator.py
│
├── collectors/
│   ├── __init__.py
│   ├── base_collector.py
│   ├── collector_factory.py
│   ├── docker_collector.py
│   ├── falco_collector.py
│   ├── forensic_collector.py
│   ├── host_collector.py
│   ├── kubernetes_collector.py
│   ├── log_collector.py
│   └── network_collector.py
│
├── config/
│   ├── __init__.py
│   └── settings.py
│
├── core/
│   ├── __init__.py
│   ├── database.py
│   ├── llm_client.py
│   ├── models.py
│   ├── queue.py
│   └── actions/
│       ├── __init__.py
│       ├── base.py
│       ├── models.py
│       ├── registry.py
│       └── executors/
│           ├── __init__.py
│           ├── delete_pod.py
│           ├── network_isolate.py
│           ├── pause_container.py
│           └── restart_container.py
│
├── ml_models/
│   ├── __init__.py
│   ├── base_detector.py
│   ├── cryptominer_detector.py
│   ├── escape_detector.py
│   ├── exfiltration_detector.py
│   ├── network_detector.py
│   ├── privilege_detector.py
│   ├── shell_detector.py
│   ├── train_with_datasets.py
│   ├── datasets/
│   │   ├── Readme.md
│   │   ├── __init__.py
│   │   ├── cicids_loader.py
│   │   ├── downloader.py
│   │   ├── nslkdd_loader.py
│   │   └── raw/
│   │       ├── KDDtest.txt
│   │       └── KDDtrain.txt
│   └── trained_models/
│       ├── cryptominer_detector.pkl
│       ├── exfiltration_detector.pkl
│       ├── network_detector.pkl
│       ├── privilege_detector.pkl
│       └── shell_detector.pkl
│
└── utils/
    ├── get_dbmetrics.py
    └── run.bat
```

---

## Overview

Traditional incident response is slow. A security analyst receives an alert, investigates manually, decides on a response, executes it, and verifies it worked. This takes 30-60 minutes on average.

This system compresses that to under 60 seconds by orchestrating six specialized AI agents that work in sequence, each with a focused responsibility, sharing context through a central intelligence layer.

---

## Architecture

The system uses a pipeline architecture where incidents flow through agents via Redis queues. A shared Context Agent serves as the intelligence backbone, assembling rich unified context from all available sources and feeding it to every agent on demand.

```
Attack Event
    ↓
Detection Agent  →  [triage queue]
    ↓
Triage Agent  (LLM: severity + confidence)  →  [decision queue]
    ↓
Decision Agent  (LLM: pick actions + trust level check)
    ↓ AUTO                    ↓ APPROVAL_REQUIRED
    |                    ApprovalManager (waits on Redis signal)
    └──────────┬──────────────┘
               ↓
        [containment queue]
               ↓
        Containment Agent  (executes action)
               ↓
        [validation queue]
               ↓
        Validation Service  (IVAM: Phase 1 → 2 → 3)
               ↓ FAIL                    ↓ PASS
        Decision Agent (retry)     [investigation queue]
        retry_number += 1               ↓
               ↑___________       Investigation Agent
                                  (root cause, IOCs, timeline)
                                        ↓
                                  [incident closed]
                                  investigation_report → SQLite


Communication Agent  ←←←←← all stages push to [notification queue]

─────────────────────────────────────────────────────────────────
Context Agent  (shared service, called directly)
    ↓ assembles from SQLite on every call
    ├── incidents, enriched_incidents, reasoning_chains
    ├── actions, action_attempts, validation_attempts
    ├── forensic_snapshot  (from ForensicCollector)
    └── similar_incident_root_causes  ← last 2 closed incidents
                                        of same type from SQLite
                                        (feeds Decision + Investigation)
```

---

## The Six Agents

### Detection Agent
Monitors Docker events in real time and runs ML-based threat classification. Uses Isolation Forest for anomaly detection alongside trained classifiers for cryptominers, data exfiltration, privilege escalation, reverse shells, and network attacks. Generates structured incident records and pushes them to the triage queue.

### Triage Agent
Pure analysis, no action decisions. Sends the incident to an LLM (Gemini 2.5 Flash) with MITRE ATT&CK mapping, asset criticality, and live forensic context. Produces a severity rating (P1-P4), confidence score, false positive determination, and a step-by-step reasoning chain. Hands off to the Decision Agent with just the essentials.

### Decision Agent
The strategic brain. Uses LLM to select the best containment actions from the registered executor pool, informed by triage analysis, forensic data, and historical root causes from similar past incidents. Then applies the Progressive Trust Engine to decide whether to auto-execute or require human approval.

**Progressive Trust Engine:**

| Level | Name | Actions Threshold | Confidence Required |
|-------|------|-------------------|---------------------|
| 1 | Learning | 0-50 | All require approval |
| 2 | Cautious | 51-150 | >= 0.95 |
| 3 | Confident | 151-500 | >= 0.90 |
| 4 | Autonomous | 500+ | >= 0.85 |

On retry after a validation failure, the LLM reads exact error messages from prior attempts to distinguish a genuine failure from a case where containment already succeeded (e.g. "Container not found" after delete_pod ran).

### Containment Agent
Executes containment actions using a plugin-based architecture with decorator auto-registration. Available executors:

- `delete_pod` - forcefully removes the compromised container
- `network_isolate` - applies egress deny network policy
- `pause_container` - freezes the container without removal
- `restart_container` - restarts with clean state
- `capture_logs` - non-destructive evidence collection

### Validation Service (IVAM)
Three-phase validation that verifies every containment action actually worked:

- **Phase 1 - Immediate (30s):** Did the action complete?
- **Phase 2 - Sustained (5min):** Is containment still holding?
- **Phase 3 - Effective:** Has the threat been eliminated?

On failure, triggers a retry loop back to the Decision Agent with incremented retry number and full failure context.

### Investigation Agent
Performs deep forensic analysis after successful containment. Fully context-driven, reads forensic artifacts already captured by the background ForensicCollector rather than running its own collection. Produces a structured investigation report covering root cause, attack vector, attacker sophistication, IOCs (IPs, domains, hashes), timeline reconstruction, and lateral movement analysis. The report is persisted to SQLite and feeds future incidents as historical intelligence.

### Communication Agent
Listens to the notification queue throughout the entire pipeline and handles all outbound messaging: real-time alerts, stage progress updates, approval requests, and post-incident reports.

---

## Context Agent

Not a pipeline stage but a shared intelligence service called directly by agents. On every call it assembles a unified context object by querying all relevant SQLite tables and the ForensicCollector concurrently:

- Base incident data and triage enrichment
- LLM reasoning chains
- All containment actions and IVAM phase results
- Live forensic snapshot (network connections, recent shell history)
- Historical root causes from the last 2 resolved incidents of the same type, stripped of per-incident recommendations, used to inform both action selection and root cause analysis

Context is cached in memory and annotated with phase_updates as the incident moves through the pipeline, so every agent sees the full history of what has happened so far.

---

## Forensic Collection

A background ForensicCollector captures per-incident forensic snapshots:

- **Network forensics** - active connections, listening ports, traffic patterns
- **Shell history** - last 10 executed commands from bash/zsh/PowerShell history

Registered with the Context Agent at startup and shared across the pipeline. Snapshots are captured as close to the incident as possible and accessed by the Investigation Agent through the Context Agent, avoiding redundant collection.

---

## Key Design Decisions

**Context-driven investigation** — Early versions had the Investigation Agent running its own collectors. Refactoring to read from the Context Agent eliminated redundant collection and gave the LLM significantly richer input: full reasoning chain, triage confidence, containment history, and validation outcomes in one object.

**Historical root causes in Decision Agent** — The Decision Agent knows what attack vectors were used in similar past incidents before selecting actions. A cryptominer that previously exploited a specific privilege escalation path informs the current response strategy.

**Recommendations stripped from historical context** — Recommendations are per-incident action items. Only the analytical findings carry forward: attack vector, root cause, sophistication, impact. Passing stale recommendations would pollute the LLM reasoning.

**LLM-driven retry logic** — On retry the LLM distinguishes a real failure from a spurious validation error. "Container not found" during Phase 2 after a successful delete_pod means the container is gone and containment succeeded. A rule-based system would incorrectly escalate.

---

## Tech Stack

| Component | Technology |
|-----------|------------|
| Agent runtime | Python 3.12 + asyncio |
| LLM | Gemini 2.5 Flash (OpenRouter fallback) |
| Queue | Redis |
| Database | SQLite (aiosqlite) |
| Container monitoring | Docker API |
| ML detection | scikit-learn (Isolation Forest + classifiers) |
| HTTP client | httpx + tenacity |
| Validation | Pydantic |
| Logging | structlog |
| API | FastAPI |
| Dashboard | Streamlit |

---

## Quick Start

**Prerequisites:** Docker, Python 3.12+, Redis

```bash
pip install -r requirements.txt

cp .env.example .env
# Add GEMINI_API_KEY and optionally OPENROUTER_API_KEY

python main.py
```

In another terminal:

```bash
python simulate.py attack cryptominer
python simulate.py attack reverse_shell
python simulate.py attack cpu_bomb
python simulate.py attack port_scan
python simulate.py attack all
```

**Environment overrides:**

```
IR_COLLECTOR=docker        Force Docker API collector (default on Windows/WSL2)
IR_COLLECTOR=falco         Force Falco collector (Linux only)
IR_DRY_RUN=true            Simulate actions without executing
IR_ENABLE_SNAPSHOTS=false  Disable forensic snapshots
```

---

## Performance Targets

| Metric | Target |
|--------|--------|
| End-to-end MTTR | < 60 seconds |
| Detection accuracy | >= 95% |
| Auto-resolution rate (Level 3+) | >= 75% |
| Action validation success | >= 98% |
| False negatives on P1 threats | 0 |

---

## Academic Context

Built as a final year project demonstrating enterprise-level software engineering applied to a real security automation problem: multi-agent AI orchestration, progressive trust systems, forensic evidence collection, and LLM-powered reasoning with transparent decision chains.