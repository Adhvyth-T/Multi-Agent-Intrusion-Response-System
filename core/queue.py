import redis.asyncio as redis
import json
from typing import Optional, Dict, Any
from config import config
import structlog

log = structlog.get_logger()

class EventQueue:
    """Redis-based event queue for inter-agent communication."""
    
    QUEUES = {
        'detection': 'ir:queue:detection',
        'triage': 'ir:queue:triage',
        'containment': 'ir:queue:containment',
        'investigation': 'ir:queue:investigation',
        'recovery': 'ir:queue:recovery',
        'notification': 'ir:queue:notification',
    }
    
    def __init__(self):
        self.redis: Optional[redis.Redis] = None
    
    async def connect(self):
        self.redis = redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            decode_responses=True
        )
        await self.redis.ping()
        log.info("Connected to Redis")
    
    async def disconnect(self):
        if self.redis:
            await self.redis.close()
    
    async def push(self, queue_name: str, event: Dict[str, Any]):
        """Push event to queue."""
        queue_key = self.QUEUES.get(queue_name, f'ir:queue:{queue_name}')
        await self.redis.lpush(queue_key, json.dumps(event))
        log.debug("Event pushed", queue=queue_name, event_id=event.get('id'))
    
    async def pop(self, queue_name: str, timeout: int = 0) -> Optional[Dict[str, Any]]:
        """Pop event from queue (blocking)."""
        queue_key = self.QUEUES.get(queue_name, f'ir:queue:{queue_name}')
        result = await self.redis.brpop(queue_key, timeout=timeout)
        if result:
            _, data = result
            return json.loads(data)
        return None
    
    async def pop_nowait(self, queue_name: str) -> Optional[Dict[str, Any]]:
        """Non-blocking pop."""
        queue_key = self.QUEUES.get(queue_name, f'ir:queue:{queue_name}')
        data = await self.redis.rpop(queue_key)
        if data:
            return json.loads(data)
        return None
    
    async def length(self, queue_name: str) -> int:
        """Get queue length."""
        queue_key = self.QUEUES.get(queue_name, f'ir:queue:{queue_name}')
        return await self.redis.llen(queue_key)
    
    async def publish(self, channel: str, message: Dict[str, Any]):
        """Publish to a pub/sub channel (for real-time updates)."""
        await self.redis.publish(f'ir:channel:{channel}', json.dumps(message))
    
    async def subscribe(self, channel: str):
        """Subscribe to a pub/sub channel."""
        pubsub = self.redis.pubsub()
        await pubsub.subscribe(f'ir:channel:{channel}')
        return pubsub

# Singleton instance
queue = EventQueue()
