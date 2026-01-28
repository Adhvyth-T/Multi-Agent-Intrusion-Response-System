#!/usr/bin/env python3
"""
Autonomous IR System - Streamlit Dashboard (COMPLETE FIX)
Fixes database schema mismatch and approval integration
"""

import streamlit as st
import subprocess
import sys
import json
import sqlite3
import redis
from datetime import datetime
from pathlib import Path

# Page config
st.set_page_config(
    page_title="Autonomous IR System",
    page_icon="🛡️",
    layout="wide"
)

# Database and Redis
DB_PATH = "ir_system.db"

@st.cache_resource
def get_redis_client():
    """Get Redis client."""
    try:
        r = redis.Redis(host='localhost', port=6379, decode_responses=True)
        r.ping()
        return r
    except:
        return None

redis_client = get_redis_client()

def get_db_schema():
    """Get actual database schema to debug column issues."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get actions table schema
        cursor.execute("PRAGMA table_info(actions)")
        columns = [row[1] for row in cursor.fetchall()]
        
        conn.close()
        return columns
    except:
        return []

def get_incidents():
    """Get incidents from database."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, type, severity, resource, namespace, status, created_at
            FROM incidents
            ORDER BY created_at DESC
            LIMIT 100
        """)
        incidents = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return incidents
    except Exception as e:
        st.error(f"Database error: {e}")
        return []

def get_pending_actions():
    """Get pending actions - handles different schema formats."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # First, check what columns exist
        cursor.execute("PRAGMA table_info(actions)")
        columns = [row[1] for row in cursor.fetchall()]
        
        # Build query based on available columns
        select_cols = ['id', 'incident_id', 'action_type', 'status', 'created_at']
        
        # Check for params/action_details/action_params
        if 'action_details' in columns:
            select_cols.append('action_details')
            params_col = 'action_details'
        elif 'params' in columns:
            select_cols.append('params')
            params_col = 'params'
        elif 'action_params' in columns:
            select_cols.append('action_params')
            params_col = 'action_params'
        else:
            params_col = None
        
        query = f"""
            SELECT {', '.join(select_cols)}
            FROM actions
            WHERE status = 'pending_approval'
            ORDER BY created_at DESC
        """
        
        cursor.execute(query)
        actions = []
        for row in cursor.fetchall():
            action_dict = dict(row)
            # Normalize params field name
            if params_col and params_col in action_dict:
                action_dict['params'] = action_dict.get(params_col)
            actions.append(action_dict)
        
        conn.close()
        return actions
    except Exception as e:
        st.error(f"Error loading actions: {e}")
        return []

def approve_action_via_cli(action_id: str):
    """Approve action using approve.py CLI."""
    try:
        result = subprocess.run(
            [sys.executable, "approve.py", "approve", action_id],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

def reject_action_via_cli(action_id: str, reason: str = "Rejected from dashboard"):
    """Reject action using approve.py CLI."""
    try:
        result = subprocess.run(
            [sys.executable, "approve.py", "reject", action_id, reason],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0, result.stdout, result.stderr
    except Exception as e:
        return False, "", str(e)

# Session state
if 'system_running' not in st.session_state:
    st.session_state.system_running = False
if 'main_process' not in st.session_state:
    st.session_state.main_process = None

# Check if process is still running
if st.session_state.main_process and st.session_state.main_process.poll() is not None:
    st.session_state.system_running = False
    st.session_state.main_process = None

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
    }
    .status-running {
        background-color: #28a745;
        color: white;
        padding: 8px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
    .status-stopped {
        background-color: #dc3545;
        color: white;
        padding: 8px;
        border-radius: 5px;
        text-align: center;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# Title
st.markdown('<div class="main-header">🛡️ Autonomous IR System</div>', unsafe_allow_html=True)

# Sidebar
st.sidebar.title("🎛️ System Control")

if st.session_state.system_running:
    st.sidebar.markdown('<div class="status-running">● RUNNING</div>', unsafe_allow_html=True)
else:
    st.sidebar.markdown('<div class="status-stopped">● STOPPED</div>', unsafe_allow_html=True)

st.sidebar.markdown("---")

# Start/Stop
col1, col2 = st.sidebar.columns(2)

with col1:
    if st.button("▶️ Start", disabled=st.session_state.system_running, use_container_width=True):
        try:
            process = subprocess.Popen([sys.executable, "main.py"])
            st.session_state.main_process = process
            st.session_state.system_running = True
            st.sidebar.success("Started!")
            st.rerun()
        except Exception as e:
            st.sidebar.error(f"Error: {e}")

with col2:
    if st.button("⏹️ Stop", disabled=not st.session_state.system_running, use_container_width=True):
        if st.session_state.main_process:
            st.session_state.main_process.terminate()
            st.session_state.main_process = None
            st.session_state.system_running = False
            st.sidebar.success("Stopped!")
            st.rerun()

st.sidebar.markdown("---")

# Connection status
st.sidebar.subheader("📡 Status")
if redis_client:
    st.sidebar.success("✅ Redis")
else:
    st.sidebar.error("❌ Redis")

if Path(DB_PATH).exists():
    st.sidebar.success("✅ Database")
else:
    st.sidebar.warning("⚠️ No DB")

# Debug info
with st.sidebar.expander("🔧 Debug Info"):
    schema = get_db_schema()
    if schema:
        st.write("**Actions table columns:**")
        for col in schema:
            st.text(f"  - {col}")

# Auto-refresh
st.sidebar.markdown("---")
auto_refresh = st.sidebar.checkbox("🔄 Auto-refresh (5s)", value=True)
if st.sidebar.button("🔄 Refresh", use_container_width=True):
    st.rerun()

# Tabs
tab1, tab2, tab3 = st.tabs(["🎯 Attacks", "⚠️ Incidents", "✅ Approvals"])

# ==================== TAB 1: ATTACKS ====================
with tab1:
    st.header("🎯 Attack Simulation")
    
    if not st.session_state.system_running:
        st.warning("⚠️ Start the system first!")
    
    cols = st.columns(3)
    
    attacks = {
        "cryptominer": "⛏️ Cryptominer",
        "reverse_shell": "🐚 Reverse Shell",
        "cpu_bomb": "💣 CPU Bomb"
    }
    
    for idx, (key, name) in enumerate(attacks.items()):
        with cols[idx]:
            if st.button(f"{name}", key=f"attack_{key}", use_container_width=True):
                with st.spinner(f"Deploying..."):
                    result = subprocess.run(
                        [sys.executable, "simulate.py", "attack", key],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    if result.returncode == 0:
                        st.success(f"✅ Deployed!")
                        with st.expander("Output"):
                            st.code(result.stdout)
                    else:
                        st.error(f"❌ Failed")
    
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 1])
    with col2:
        if st.button("🚨 DEPLOY ALL", type="primary", use_container_width=True):
            result = subprocess.run(
                [sys.executable, "simulate.py", "attack", "all"],
                capture_output=True,
                text=True,
                timeout=60
            )
            if result.returncode == 0:
                st.success("✅ All deployed!")
    
    st.markdown("---")
    if st.button("🗑️ Stop All Attacks"):
        subprocess.run([sys.executable, "simulate.py", "cleanup-all"])
        st.success("Stopped")

# ==================== TAB 2: INCIDENTS ====================
with tab2:
    st.header("⚠️ Incidents")
    
    incidents = get_incidents()
    
    if incidents:
        st.write(f"**Total:** {len(incidents)}")
        
        for inc in incidents:
            severity = inc.get('severity', 'P3')
            
            if severity == 'P1':
                color = "#dc3545"
            elif severity == 'P2':
                color = "#fd7e14"
            else:
                color = "#ffc107"
            
            col1, col2, col3 = st.columns([1, 4, 2])
            
            with col1:
                st.markdown(f'<div style="background:{color};color:white;padding:8px;border-radius:3px;text-align:center;font-weight:bold">{severity}</div>', unsafe_allow_html=True)
            
            with col2:
                st.write(f"**{inc.get('type', 'Unknown')}**")
                st.caption(f"{inc.get('id', '')[:8]} | {inc.get('resource', '')}")
            
            with col3:
                st.write(f"**{inc.get('status', 'Unknown')}**")
                st.caption(inc.get('created_at', '')[:19])
            
            st.markdown("---")
    else:
        st.info("No incidents. Deploy an attack!")

# ==================== TAB 3: APPROVALS ====================
with tab3:
    st.header("✅ Action Approvals")
    
    actions = get_pending_actions()
    
    if actions:
        st.write(f"**Pending:** {len(actions)}")
        st.markdown("---")
        
        for action in actions:
            action_id = action.get('id', 'unknown')
            action_type = action.get('action_type', 'unknown')
            incident_id = action.get('incident_id', 'unknown')
            created_at = action.get('created_at', '')
            
            with st.container():
                st.subheader(f"🔐 {action_type}")
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    st.write(f"**Action ID:** `{action_id}`")
                    st.write(f"**Incident:** `{incident_id[:8]}`")
                    st.write(f"**Created:** {created_at[:19]}")
                    
                    # Show params if available
                    params = action.get('params')
                    if params:
                        try:
                            if isinstance(params, str):
                                params = json.loads(params)
                            st.json(params)
                        except:
                            st.code(str(params))
                
                with col2:
                    st.write("**Decision:**")
                    
                    col_a, col_r = st.columns(2)
                    
                    with col_a:
                        if st.button("✅ Approve", key=f"approve_{action_id}", use_container_width=True):
                            success, stdout, stderr = approve_action_via_cli(action_id)
                            if success:
                                st.success("Approved!")
                                st.rerun()
                            else:
                                st.error(f"Failed: {stderr}")
                    
                    with col_r:
                        if st.button("❌ Reject", key=f"reject_{action_id}", use_container_width=True):
                            success, stdout, stderr = reject_action_via_cli(action_id)
                            if success:
                                st.warning("Rejected!")
                                st.rerun()
                            else:
                                st.error(f"Failed: {stderr}")
                
                st.markdown("---")
    else:
        st.info("No pending approvals")
        
        # Debug help
        with st.expander("🔍 Troubleshooting"):
            st.write("**If approvals aren't showing:**")
            st.code("""
# 1. Check database
python debug_data.py

# 2. Check actions table
sqlite3 ir_system.db "SELECT * FROM actions WHERE status='pending_approval';"

# 3. Check logs for approval creation
            """)

# Auto-refresh
if auto_refresh:
    import time
    time.sleep(5)
    st.rerun()

# Footer
st.markdown("---")
st.markdown("**Autonomous IR System** | Real-time monitoring")