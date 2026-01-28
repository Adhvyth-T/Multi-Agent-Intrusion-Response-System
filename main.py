"""
Autonomous Incident Response System - Main Entry Point
"""

import asyncio
import signal
import sys
import platform
import structlog

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
    from agents import detection_agent, communication_agent, triage_agent, trust_engine
    from agents.event_collectors import falco_collector  # Event collector for Falco

    # Initialize database
    log.info("Initializing database...")
    await init_db()
    
    # Connect to Redis
    log.info("Connecting to Redis...")
    await queue.connect()
    
    # Create tasks for all agents
    agents = []
    
    log.info("Starting agents...")
    
    # Start Falco Event Collector FIRST (feeds detection agent)
    agents.append(asyncio.create_task(falco_collector.start(), name="falco_collector"))
    log.info("✓ Falco Event Collector started")
    
    # Start Communication Agent (handles all notifications)
    agents.append(asyncio.create_task(communication_agent.start(), name="communication"))
    log.info("✓ Communication Agent started")
    
    # Start Detection Agent (processes events from Falco)
    agents.append(asyncio.create_task(detection_agent.start(), name="detection"))
    log.info("✓ Detection Agent started")
    
    # Start Triage Agent (analyzes incidents with LLM)
    agents.append(asyncio.create_task(triage_agent.start(), name="triage"))
    log.info("✓ Triage Agent started")
    
    # Start Trust Engine (decides auto vs approval)
    agents.append(asyncio.create_task(trust_engine.start(), name="trust_engine"))
    log.info("✓ Progressive Trust Engine started")
    
    log.info("="*60)
    log.info("🚀 Autonomous IR System Ready")
    log.info("="*60)
    log.info("System Status:")
    log.info("  ✓ Falco collector monitoring Docker containers")
    log.info("  ✓ Detection agent analyzing events with ML")
    log.info("  ✓ Triage agent ready for LLM analysis")
    log.info("  ✓ Trust engine initialized at Level 1")
    log.info("="*60)
    log.info("Test Commands:")
    log.info("  python simulate.py attack cryptominer")
    log.info("  python simulate.py attack reverse_shell")
    log.info("  python simulate.py attack cpu_bomb")
    log.info("  python simulate.py attack all")
    log.info("="*60)
    log.info("Waiting for events... (Press Ctrl+C to stop)")
    log.info("")
    
    # Handle shutdown gracefully
    shutdown_event = asyncio.Event()
    
    def signal_handler(*args):
        log.info("Shutdown signal received...")
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
    log.info("Stopping agents...")
    falco_collector.running = False
    detection_agent.running = False
    communication_agent.running = False
    triage_agent.running = False
    trust_engine.running = False
    
    # Cancel all tasks
    for task in agents:
        task.cancel()
    
    # Wait for all tasks to complete
    await asyncio.gather(*agents, return_exceptions=True)
    
    # Disconnect from Redis
    await queue.disconnect()
    
    log.info("Shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("\nKeyboard interrupt received, exiting...")
    except Exception as e:
        log.error("Fatal error", error=str(e), exc_info=True)
        sys.exit(1)