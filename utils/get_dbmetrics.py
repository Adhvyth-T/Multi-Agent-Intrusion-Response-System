#!/usr/bin/env python3
"""
Progressive Trust Engine - Summary Report
Shows trust level, action history, success rates, and progression
"""

import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = "ir_system.db"

def get_trust_summary():
    """Generate comprehensive trust engine summary."""
    if not Path(DB_PATH).exists():
        print("❌ Database not found!")
        return
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("="*70)
    print(" "*20 + "PROGRESSIVE TRUST ENGINE SUMMARY")
    print("="*70)
    print()
    
    # ==================== CURRENT TRUST LEVEL ====================
    print("📊 CURRENT TRUST LEVEL")
    print("-"*70)
    
    try:
        cursor.execute("""
            SELECT current_level, total_actions, successful_actions, failed_actions,
                   level_changed_at
            FROM trust_metrics
            LIMIT 1
        """)
        
        trust_data = cursor.fetchone()
        
        if trust_data:
            level, total, success, failed, changed_at = trust_data
            success_rate = (success / total * 100) if total > 0 else 0
            
            # Trust level names
            levels = {
                1: "Learning (Manual approval for everything)",
                2: "Cautious (High confidence required)",
                3: "Confident (Auto-execute P2/P3)",
                4: "Autonomous (Full automation)"
            }
            
            print(f"  Level: {level} - {levels.get(level, 'Unknown')}")
            print(f"  Total Actions: {total}")
            print(f"  Successful: {success} ({success_rate:.1f}%)")
            print(f"  Failed: {failed}")
            print(f"  Last Level Change: {changed_at or 'Never'}")
            
            # Progress to next level
            if level < 4:
                thresholds = {
                    1: (50, "Next: Level 2 (Cautious) at 50 actions"),
                    2: (150, "Next: Level 3 (Confident) at 150 actions"),
                    3: (500, "Next: Level 4 (Autonomous) at 500 actions")
                }
                
                threshold, msg = thresholds.get(level, (0, ""))
                remaining = threshold - total
                progress = (total / threshold * 100) if threshold > 0 else 100
                
                print(f"\n  Progress to Next Level:")
                print(f"  [{total}/{threshold}] {progress:.1f}% - {remaining} actions remaining")
                print(f"  {msg}")
        else:
            print("  No trust metrics found (system not initialized)")
    except sqlite3.OperationalError:
        print("  ⚠️ Trust metrics table not found")
        print("  The trust engine hasn't created metrics yet")
    
    print()
    
    # ==================== ACTION BREAKDOWN ====================
    print("📋 ACTION BREAKDOWN")
    print("-"*70)
    
    cursor.execute("""
        SELECT status, COUNT(*) as count
        FROM actions
        GROUP BY status
        ORDER BY count DESC
    """)
    
    print("  Status Distribution:")
    for status, count in cursor.fetchall():
        print(f"    {status:20s}: {count:4d}")
    
    print()
    
    # ==================== ACTION SUCCESS RATES ====================
    print("✅ ACTION SUCCESS RATES (by type)")
    print("-"*70)
    
    cursor.execute("""
        SELECT action_type, 
               COUNT(*) as total,
               SUM(CASE WHEN status = 'completed' OR status = 'approved' THEN 1 ELSE 0 END) as successful
        FROM actions
        GROUP BY action_type
        ORDER BY total DESC
        LIMIT 10
    """)
    
    print(f"  {'Action Type':<30s} {'Total':>8s} {'Success':>8s} {'Rate':>8s}")
    print("  " + "-"*66)
    
    for action_type, total, successful in cursor.fetchall():
        rate = (successful / total * 100) if total > 0 else 0
        print(f"  {action_type:<30s} {total:>8d} {successful:>8d} {rate:>7.1f}%")
    
    print()
    
    # ==================== AUTO vs MANUAL ====================
    print("🤖 AUTOMATION STATISTICS")
    print("-"*70)
    
    cursor.execute("""
        SELECT 
            SUM(CASE WHEN approved_by IS NULL OR approved_by = 'auto' THEN 1 ELSE 0 END) as auto_count,
            SUM(CASE WHEN approved_by IS NOT NULL AND approved_by != 'auto' THEN 1 ELSE 0 END) as manual_count,
            COUNT(*) as total
        FROM actions
        WHERE status != 'pending_approval'
    """)
    
    auto, manual, total = cursor.fetchone()
    auto = auto or 0
    manual = manual or 0
    
    if total > 0:
        auto_rate = (auto / total * 100)
        manual_rate = (manual / total * 100)
        
        print(f"  Auto-approved:   {auto:4d} ({auto_rate:5.1f}%)")
        print(f"  Manual-approved: {manual:4d} ({manual_rate:5.1f}%)")
        print(f"  Total Processed: {total:4d}")
    else:
        print("  No processed actions yet")
    
    print()
    
    # ==================== RECENT ACTIVITY ====================
    print("📅 RECENT ACTIVITY (Last 10 actions)")
    print("-"*70)
    
    cursor.execute("""
        SELECT id, action_type, status, approved_by, created_at
        FROM actions
        ORDER BY created_at DESC
        LIMIT 10
    """)
    
    print(f"  {'ID':<12s} {'Action':<20s} {'Status':<20s} {'Approved By':<15s} {'Time':<20s}")
    print("  " + "-"*66)
    
    for action_id, action_type, status, approved_by, created in cursor.fetchall():
        approved_by = approved_by or "N/A"
        created = created[:19] if created else "N/A"
        print(f"  {action_id:<12s} {action_type:<20s} {status:<20s} {approved_by:<15s} {created:<20s}")
    
    print()
    
    # ==================== INCIDENT CORRELATION ====================
    print("🔗 INCIDENT CORRELATION")
    print("-"*70)
    
    cursor.execute("""
        SELECT i.severity, COUNT(DISTINCT a.id) as action_count
        FROM incidents i
        LEFT JOIN actions a ON i.id = a.incident_id
        GROUP BY i.severity
        ORDER BY 
            CASE i.severity 
                WHEN 'P1' THEN 1
                WHEN 'P2' THEN 2
                WHEN 'P3' THEN 3
                ELSE 4
            END
    """)
    
    print(f"  {'Severity':<10s} {'Actions Generated':>20s}")
    print("  " + "-"*32)
    
    for severity, count in cursor.fetchall():
        print(f"  {severity:<10s} {count:>20d}")
    
    print()
    
    # ==================== RECOMMENDATIONS ====================
    print("💡 RECOMMENDATIONS")
    print("-"*70)
    
    # Get current level for recommendations
    cursor.execute("SELECT current_level, total_actions, successful_actions FROM trust_metrics LIMIT 1")
    trust_data = cursor.fetchone()
    
    if trust_data:
        level, total, success = trust_data
        success_rate = (success / total * 100) if total > 0 else 0
        
        recommendations = []
        
        if level == 1 and total >= 50 and success_rate >= 95:
            recommendations.append("✅ Ready to upgrade to Level 2 (Cautious)")
        elif level == 2 and total >= 150 and success_rate >= 95:
            recommendations.append("✅ Ready to upgrade to Level 3 (Confident)")
        elif level == 3 and total >= 500 and success_rate >= 95:
            recommendations.append("✅ Ready to upgrade to Level 4 (Autonomous)")
        
        if success_rate < 90 and level > 1:
            recommendations.append("⚠️ Success rate below 90% - consider downgrading trust level")
        
        if success_rate >= 95 and total > 100:
            recommendations.append("✅ High success rate - system is performing well")
        
        # Check pending approvals
        cursor.execute("SELECT COUNT(*) FROM actions WHERE status = 'pending_approval'")
        pending = cursor.fetchone()[0]
        if pending > 20:
            recommendations.append(f"⚠️ {pending} pending approvals - consider approving or adjusting trust level")
        
        if recommendations:
            for rec in recommendations:
                print(f"  {rec}")
        else:
            print("  No specific recommendations at this time")
    else:
        print("  Trust metrics not initialized yet")
    
    print()
    print("="*70)
    
    conn.close()

if __name__ == "__main__":
    get_trust_summary()