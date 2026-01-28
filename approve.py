#!/usr/bin/env python3
"""
CLI tool to approve/reject pending actions
"""

import asyncio
import sys
from core import queue

async def list_pending():
    """List all pending approvals."""
    # This would query your database for pending actions
    print("Pending approvals:")
    print("(In a full implementation, this would show actual pending actions)")

async def approve_action(action_id: str):
    """Approve a specific action."""
    await queue.connect()
    
    await queue.push(f"approval:{action_id}", {
        "approved": True,
        "approved_by": "cli-user",
        "approved_at": "now"
    })
    
    print(f"✅ Approved action: {action_id}")
    await queue.disconnect()

async def reject_action(action_id: str, reason: str = ""):
    """Reject a specific action."""
    await queue.connect()
    
    await queue.push(f"approval:{action_id}", {
        "approved": False,
        "rejected_by": "cli-user",
        "reason": reason,
        "rejected_at": "now"
    })
    
    print(f"❌ Rejected action: {action_id}")
    await queue.disconnect()

async def main():
    if len(sys.argv) < 2:
        print("""
Usage:
  python approve.py list                    # List pending approvals
  python approve.py approve <action_id>     # Approve an action
  python approve.py reject <action_id>      # Reject an action
  
Example:
  python approve.py approve act-inc1-1
        """)
        return
    
    command = sys.argv[1]
    
    if command == "list":
        await list_pending()
    elif command == "approve" and len(sys.argv) >= 3:
        action_id = sys.argv[2]
        await approve_action(action_id)
    elif command == "reject" and len(sys.argv) >= 3:
        action_id = sys.argv[2]
        reason = sys.argv[3] if len(sys.argv) > 3 else "No reason provided"
        await reject_action(action_id, reason)
    else:
        print("Invalid command. Use 'list', 'approve', or 'reject'")

if __name__ == "__main__":
    asyncio.run(main())