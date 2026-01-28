# Autonomous Incident Response System

AI-powered security incident detection, triage, and response system with progressive trust.

## Quick Start(api)

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure API keys
cp .env.example .env
# Edit .env with your Gemini/OpenRouter API keys

# 3. Start Redis (if not running)
redis-server

# 4. Start the system
python main.py

# 5. In another terminal, simulate attacks
python simulate.py single cryptominer
python simulate.py batch 5
python simulate.py status
```
## Run streamlit app via cmd line(Windows)
```bash
.\run.bat
```
## Architecture

```
Detection Agent → Triage Agent → Trust Engine → [Containment Queue]
       ↓              ↓              ↓
Communication Agent (Email + Terminal notifications)
```

## Agents (Week 1-2)

| Agent | Purpose |
|-------|---------|
| Detection | Monitors events, ML anomaly detection, threat classification |
| Communication | Email (SMTP) and terminal alerts |
| Triage | LLM-powered analysis, MITRE mapping, reasoning chains |
| Trust Engine | Progressive trust levels, auto/approval decisions |

## Trust Levels

| Level | Name | Actions | Auto-approve |
|-------|------|---------|--------------|
| 1 | Learning | 0-50 | Never |
| 2 | Cautious | 51-150 | Confidence ≥ 95% |
| 3 | Confident | 151-500 | Confidence ≥ 90% |
| 4 | Autonomous | 500+ | Confidence ≥ 85% |

## Attack Types

- `cryptominer` - Crypto mining detection
- `data_exfiltration` - Data theft attempts
- `privilege_escalation` - Sudo/permission abuse
- `reverse_shell` - Remote shell connections
- `container_escape` - Container breakout attempts

## Commands

```bash
python simulate.py list              # List attack types
python simulate.py single cryptominer # Single attack
python simulate.py batch 5           # 5 random attacks
python simulate.py status            # System status
python simulate.py approve <action_id> # Approve pending action
```
