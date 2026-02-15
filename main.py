# main.py
"""
Autonomous Incident Response System - Main Entry Point
"""

import asyncio
import signal
import sys
import platform
import structlog
import os

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.dev.ConsoleRenderer(colors=True)
    ],
    wrapper_class=structlog.make_filtering_bound_logger(20),  # INFO level
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
)

log = structlog.get_logger()


async def main():
    """Main entry point - starts all agents."""
    from core import init_db, queue
    from core.actions import ActionRegistry
    from agents import (
        detection_agent, communication_agent, triage_agent, 
        trust_engine, containment_agent,validation_service, investigation_agent
    )
    from collectors import CollectorFactory
    from config import config
    
    log.info("="*60)
    log.info("🚀 Autonomous Incident Response System")
    log.info("="*60)
    
    # Show configuration
    if config.DRY_RUN:
        log.warning("🧪 DRY RUN MODE ENABLED - Actions will be simulated")
    
    # Initialize database
    log.info("Initializing database...")
    await init_db()
    
    # Connect to Redis
    log.info("Connecting to Redis...")
    await queue.connect()
    
    # Show available action executors
    log.info("")
    log.info("="*60)
    log.info("⚙️  Action Execution System")
    log.info("="*60)
    available_actions = ActionRegistry.list_available()
    capabilities = ActionRegistry.get_capabilities()
    
    log.info(f"Registered action executors: {len(available_actions)}")
    for action_name in available_actions:
        cap = capabilities.get(action_name)
        if cap:
            destructive_marker = "🔴" if cap.destructive else "🟢"
            reversible_marker = "↩️" if cap.reversible else "  "
            log.info(f"  {destructive_marker} {reversible_marker} {action_name:<20} - {cap.description}")
        else:
            log.info(f"     {action_name}")
    
    log.info("")
    log.info("Legend:")
    log.info("  🔴 = Destructive action")
    log.info("  🟢 = Non-destructive action")
    log.info("  ↩️ = Reversible action")
    
    # Environment detection and collector selection
    log.info("")
    log.info("="*60)
    log.info("🔍 Environment Detection & Collector Selection")
    log.info("="*60)
    
    # Show available collectors
    available = await CollectorFactory.get_available_collectors()
    log.info("Scanning for available collectors...")
    for name, status in available.items():
        symbol = "✓" if status else "✗"
        status_text = "AVAILABLE" if status else "not available"
        log.info(f"  {symbol} {name.upper():<15} - {status_text}")
    
    # Check for environment override
    env_override = os.getenv('IR_COLLECTOR')
    if env_override:
        log.info(f"")
        log.info(f"📌 Environment override detected: IR_COLLECTOR={env_override}")
    
    # Create the best collector for this environment
    try:
        collector = await CollectorFactory.create_all_collectors()
        security_collector = collector['security']
        log.info("")
        log.info(f"✨ Selected: {security_collector.name.upper()}")
        log.info(f"✨ Investigation Collectors: {len(collector) - 1} ready")
        log.info("="*60)
        
        # Show collector capabilities
        capabilities = security_collector.get_capabilities()
        log.info("Collector Capabilities:")
        for cap, enabled in capabilities.items():
            if enabled:
                log.info(f"  ✓ {cap}")
        
    except RuntimeError as e:
        log.error(f"Failed to create collector: {e}")
        log.error("Ensure Docker is running or Falco is installed")
        sys.exit(1)
    
    log.info("="*60)
    log.info("")
    
    # Create tasks for all agents
    agents = []
    
    log.info("Starting system components...")
    log.info("")
    
    # Start Event Collector FIRST (feeds detection agent)
    agents.append(asyncio.create_task(security_collector.start(), name="event_collector"))
    log.info(f"✓ Event Collector started ({security_collector.name})")
    
    # Start Communication Agent (handles all notifications)
    agents.append(asyncio.create_task(communication_agent.start(), name="communication"))
    log.info("✓ Communication Agent started")
    
    # Start Detection Agent (processes events from collector)
    agents.append(asyncio.create_task(detection_agent.start(), name="detection"))
    log.info("✓ Detection Agent started")
    
    # Start Triage Agent (analyzes incidents with LLM)
    agents.append(asyncio.create_task(triage_agent.start(), name="triage"))
    log.info("✓ Triage Agent started")
    
    # Start Trust Engine (decides auto vs approval)
    agents.append(asyncio.create_task(trust_engine.start(), name="trust_engine"))
    log.info("✓ Progressive Trust Engine started")
    
    # Start Containment Agent (executes actions)
    agents.append(asyncio.create_task(containment_agent.start(), name="containment"))
    log.info("✓ Containment Agent started")
    
    # Start Validation Service (Validates actions and provides feedback)
    validation_task = asyncio.create_task(validation_service.start(), name="validation_service")
    agents.append(validation_task)
    log.info("✓ Validation Service started")

        # Start Investigation Agent (Performs deeper analysis and forensics)
    agents.append(asyncio.create_task(investigation_agent.start(), name="investigation"))
    log.info("✓ Investigation Agent started")
    
    log.info("")
    log.info("="*60)
    log.info("🎯 System Status: OPERATIONAL")
    log.info("="*60)
    
    # Show system configuration
    log.info("Configuration:")
    log.info(f"  • Event Collector: {security_collector.name}")
    log.info(f"  • Detection: ML-based anomaly detection")
    log.info(f"  • Triage: LLM-powered analysis")
    log.info(f"  • Trust Level: Level 1 (Learning mode)")
    log.info(f"  • Containment: {len(available_actions)} action executors")
    log.info(f"  • Database: SQLite (local)")
    log.info(f"  • Queue: Redis")
    log.info(f"  • Dry Run: {'ENABLED' if config.DRY_RUN else 'DISABLED'}")
    
    log.info("")
    log.info("="*60)
    log.info("🧪 Test Attack Simulations")
    log.info("="*60)
    log.info("Run these commands in another terminal:")
    log.info("")
    log.info("  python simulate.py attack cryptominer")
    log.info("  python simulate.py attack reverse_shell")
    log.info("  python simulate.py attack cpu_bomb")
    log.info("  python simulate.py attack port_scan")
    log.info("  python simulate.py attack all")
    log.info("")
    
    log.info("="*60)
    log.info("⚙️  Environment Variables")
    log.info("="*60)
    log.info("Override settings:")
    log.info("")
    log.info("  IR_COLLECTOR=docker        - Force Docker API collector")
    log.info("  IR_COLLECTOR=falco         - Force Falco collector (Linux)")
    log.info("  IR_COLLECTOR=kubernetes    - Force K8s API collector")
    log.info("  IR_DRY_RUN=true            - Enable dry run mode")
    log.info("  IR_ENABLE_SNAPSHOTS=false  - Disable forensic snapshots")
    log.info("")
    current_collector = os.getenv('IR_COLLECTOR', 'auto-detect')
    current_dry_run = os.getenv('IR_DRY_RUN', 'false')
    log.info(f"Current: IR_COLLECTOR={current_collector}, IR_DRY_RUN={current_dry_run}")
    log.info("")
    
    log.info("="*60)
    log.info("📊 Monitoring")
    log.info("="*60)
    log.info("Watch for events... (Press Ctrl+C to stop)")
    log.info("")
    
    # Handle shutdown gracefully
    shutdown_event = asyncio.Event()
    
    def signal_handler(*args):
        log.info("")
        log.info("="*60)
        log.info("🛑 Shutdown signal received...")
        log.info("="*60)
        shutdown_event.set()
    
    # Cross-platform signal handling
    if platform.system() != "Windows":
        # Unix/Linux/Mac - use asyncio signal handlers
        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    else:
        # Windows - use signal.signal
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # Wait for shutdown signal or agent completion
        await shutdown_event.wait()
    except asyncio.CancelledError:
        log.info("Main task cancelled")
    
    # Stop all agents
    log.info("Stopping system components...")
    
    # Stop collector
    await security_collector.stop()
    
    # Stop agents
    detection_agent.running = False
    communication_agent.running = False
    triage_agent.running = False
    trust_engine.running = False
    containment_agent.running = False
    investigation_agent.running = False
    
    # Cancel all tasks
    for task in agents:
        task.cancel()
    
    # Wait for all tasks to complete
    await asyncio.gather(*agents, return_exceptions=True)
    
    # Disconnect from Redis
    await queue.disconnect()
    
    # Show final stats
    log.info("")
    log.info("="*60)
    log.info("📈 Final Statistics")
    log.info("="*60)
    
    # Collector stats
    collector_metrics = security_collector.get_metrics()
    log.info(f"Collector:")
    log.info(f"  Events processed: {collector_metrics['events_processed']}")
    log.info(f"  Threats detected: {collector_metrics['threats_detected']}")
    log.info(f"  Errors: {collector_metrics['errors']}")
    
    # Containment stats
    containment_stats = containment_agent.get_stats()
    log.info(f"Containment:")
    log.info(f"  Actions executed: {containment_stats['total_executions']}")
    log.info(f"  Successful: {containment_stats['successful']}")
    log.info(f"  Failed: {containment_stats['failed']}")
    log.info(f"  Success rate: {containment_stats['success_rate']:.1%}")
    
    log.info(f"Uptime: {collector_metrics['uptime_seconds']:.1f}s")
    log.info("")
    
    log.info("="*60)
    log.info("✅ Shutdown complete")
    log.info("="*60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("\n\n🛑 Keyboard interrupt received, exiting...")
    except Exception as e:
        log.error("💥 Fatal error", error=str(e), exc_info=True)
        sys.exit(1)
