# simulate.py (FIXED)
#!/usr/bin/env python3
"""
Real attack simulator CLI - deploys actual attack containers.
Usage:
    python simulate.py attack cryptominer
    python simulate.py attack reverse_shell
    python simulate.py attack cpu_bomb
    python simulate.py attack all
    python simulate.py cleanup <container_id>
    python simulate.py cleanup-all
"""

import asyncio
import sys
import logging  # ADD THIS IMPORT
import structlog

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(colors=True)
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger()

async def main():
    from attack_simulator.real_attacks import real_attacker
    from core import queue
    
    # Connect to Redis
    await queue.connect()
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python simulate.py attack cryptominer")
        print("  python simulate.py attack reverse_shell")
        print("  python simulate.py attack cpu_bomb")
        print("  python simulate.py attack all")
        print("  python simulate.py cleanup <container_id>")
        print("  python simulate.py cleanup-all")
        await queue.disconnect()
        return
    
    cmd = sys.argv[1]
    
    if cmd == "attack":
        if len(sys.argv) < 3:
            print("Specify attack type: cryptominer, reverse_shell, cpu_bomb, or all")
            await queue.disconnect()
            return
        
        attack_type = sys.argv[2]
        
        if attack_type == "cryptominer":
            container_id = await real_attacker.attack_cryptominer()
            print(f"\n✅ CRYPTOMINER DEPLOYED: {container_id}")
            print(f"   Falco should detect this in 5-10 seconds...")
            print(f"   To stop: python simulate.py cleanup {container_id}\n")
        
        elif attack_type == "reverse_shell":
            container_id = await real_attacker.attack_reverse_shell()
            print(f"\n✅ REVERSE SHELL DEPLOYED: {container_id}")
            print(f"   Falco should detect this in 5-10 seconds...")
            print(f"   To stop: python simulate.py cleanup {container_id}\n")
        
        elif attack_type == "cpu_bomb":
            container_id = await real_attacker.attack_cpu_bomb()
            print(f"\n✅ CPU BOMB DEPLOYED: {container_id}")
            print(f"   Falco should detect this in 5-10 seconds...")
            print(f"   To stop: python simulate.py cleanup {container_id}\n")
        
        elif attack_type == "all":
            print("\n🚨 DEPLOYING ALL ATTACKS...\n")
            
            c1 = await real_attacker.attack_cryptominer()
            print(f"✅ Cryptominer: {c1}")
            await asyncio.sleep(2)
            
            c2 = await real_attacker.attack_reverse_shell()
            print(f"✅ Reverse Shell: {c2}")
            await asyncio.sleep(2)
            
            c3 = await real_attacker.attack_cpu_bomb()
            print(f"✅ CPU Bomb: {c3}")
            
            print("\n🎯 All attacks deployed!")
            print(f"   To stop all: python simulate.py cleanup-all\n")
        
        else:
            print(f"Unknown attack type: {attack_type}")
    
    elif cmd == "cleanup":
        if len(sys.argv) < 3:
            print("Usage: python simulate.py cleanup <container_id>")
        else:
            container_id = sys.argv[2]
            await real_attacker.cleanup_attack(container_id)
            print(f"✅ Cleaned up: {container_id}")
    
    elif cmd == "cleanup-all":
        await real_attacker.cleanup_all()
        print("✅ All attack containers stopped")
    
    else:
        print(f"Unknown command: {cmd}")
    
    await queue.disconnect()

if __name__ == "__main__":
    asyncio.run(main())