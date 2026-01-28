import aiosqlite
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from config import config

DB_PATH = config.sqlite_path

async def init_db():
    """Initialize database with all required tables."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            -- Incidents table
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'P4',
                status TEXT DEFAULT 'detected',
                source TEXT,
                resource TEXT,
                namespace TEXT,
                raw_event TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Enriched incidents (from Triage)
            CREATE TABLE IF NOT EXISTS enriched_incidents (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                severity TEXT,
                confidence REAL,
                recommended_actions TEXT,
                action_mode TEXT,
                context TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );
            
            -- Reasoning chains
            CREATE TABLE IF NOT EXISTS reasoning_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL,
                step_number INTEGER,
                step_type TEXT,
                content TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );
            
            -- Actions taken
            CREATE TABLE IF NOT EXISTS actions (
                id TEXT PRIMARY KEY,
                incident_id TEXT NOT NULL,
                action_type TEXT NOT NULL,
                params TEXT,
                status TEXT DEFAULT 'pending',
                result TEXT,
                approved_by TEXT,
                executed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (incident_id) REFERENCES incidents(id)
            );
            
            -- Trust metrics
            CREATE TABLE IF NOT EXISTS trust_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                total_actions INTEGER DEFAULT 0,
                successful_actions INTEGER DEFAULT 0,
                failed_actions INTEGER DEFAULT 0,
                current_level INTEGER DEFAULT 1,
                level_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Action history for trust calculation
            CREATE TABLE IF NOT EXISTS action_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action_type TEXT NOT NULL,
                incident_type TEXT,
                success INTEGER DEFAULT 0,
                confidence REAL,
                analyst_rating INTEGER,
                feedback TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Notifications sent
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT,
                channel TEXT,
                message TEXT,
                status TEXT DEFAULT 'pending',
                sent_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            -- Initialize trust metrics if not exists
            INSERT OR IGNORE INTO trust_metrics (id, total_actions, current_level) 
            VALUES (1, 0, 1);
        """)
        await db.commit()

async def save_incident(incident: Dict[str, Any]) -> str:
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO incidents (id, type, severity, status, source, resource, namespace, raw_event)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident['id'],
            incident['type'],
            incident.get('severity', 'P4'),
            incident.get('status', 'detected'),
            incident.get('source'),
            incident.get('resource'),
            incident.get('namespace'),
            json.dumps(incident.get('raw_event', {}))
        ))
        await db.commit()
    return incident['id']

async def update_incident(incident_id: str, updates: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [incident_id]
        await db.execute(f"""
            UPDATE incidents SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, values)
        await db.commit()

async def get_incident(incident_id: str) -> Optional[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)) as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else None

async def save_enriched_incident(enriched: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO enriched_incidents (id, incident_id, severity, confidence, recommended_actions, action_mode, context)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            enriched['id'],
            enriched['incident_id'],
            enriched['severity'],
            enriched['confidence'],
            json.dumps(enriched.get('recommended_actions', [])),
            enriched['action_mode'],
            json.dumps(enriched.get('context', {}))
        ))
        await db.commit()

async def save_reasoning_chain(incident_id: str, chain: List[Dict]):
    async with aiosqlite.connect(DB_PATH) as db:
        for i, step in enumerate(chain):
            await db.execute("""
                INSERT INTO reasoning_chains (incident_id, step_number, step_type, content, confidence)
                VALUES (?, ?, ?, ?, ?)
            """, (incident_id, i, step.get('type'), step.get('content'), step.get('confidence')))
        await db.commit()

async def save_action(action: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO actions (id, incident_id, action_type, params, status)
            VALUES (?, ?, ?, ?, ?)
        """, (
            action['id'],
            action['incident_id'],
            action['action_type'],
            json.dumps(action.get('params', {})),
            action.get('status', 'pending')
        ))
        await db.commit()

async def update_action(action_id: str, updates: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values()) + [action_id]
        await db.execute(f"UPDATE actions SET {set_clause} WHERE id = ?", values)
        await db.commit()

async def get_trust_metrics() -> Dict:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM trust_metrics WHERE id = 1") as cursor:
            row = await cursor.fetchone()
            return dict(row) if row else {}

async def update_trust_metrics(updates: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        set_clause = ", ".join([f"{k} = ?" for k in updates.keys()])
        values = list(updates.values())
        await db.execute(f"""
            UPDATE trust_metrics SET {set_clause}, updated_at = CURRENT_TIMESTAMP WHERE id = 1
        """, values)
        await db.commit()

async def save_action_history(history: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO action_history (action_type, incident_type, success, confidence, analyst_rating, feedback)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            history['action_type'],
            history.get('incident_type'),
            1 if history.get('success') else 0,
            history.get('confidence'),
            history.get('analyst_rating'),
            history.get('feedback')
        ))
        await db.commit()

async def get_similar_actions(action_type: str, limit: int = 50) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM action_history WHERE action_type = ? 
            ORDER BY created_at DESC LIMIT ?
        """, (action_type, limit)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

async def save_notification(notification: Dict[str, Any]):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO notifications (incident_id, channel, message, status, sent_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            notification.get('incident_id'),
            notification['channel'],
            notification['message'],
            notification.get('status', 'pending'),
            notification.get('sent_at')
        ))
        await db.commit()

async def get_recent_incidents(limit: int = 10) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?
        """, (limit,)) as cursor:
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]
