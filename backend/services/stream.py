"""In-process WebSocket stream manager for real-time DNS events."""
from __future__ import annotations
import asyncio
from typing import Dict, Set, Any, Deque
from collections import deque
from datetime import datetime

class StreamManager:
    def __init__(self, max_buffer: int = 500):
        self.clients: Set[asyncio.Queue] = set()
        self.buffer: Deque[dict] = deque(maxlen=max_buffer)
        self.lock = asyncio.Lock()

    async def connect(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        async with self.lock:
            # Seed with recent buffer snapshot
            for item in list(self.buffer):
                await q.put(item)
            self.clients.add(q)
        return q

    async def disconnect(self, q: asyncio.Queue):
        async with self.lock:
            self.clients.discard(q)

    async def broadcast(self, payload: dict):
        payload['ts_sent'] = datetime.utcnow().isoformat() + 'Z'
        async with self.lock:
            self.buffer.append(payload)
            dead = []
            for q in self.clients:
                try:
                    if q.full():
                        # Drop oldest by getting one item
                        _ = q.get_nowait()
                    q.put_nowait(payload)
                except Exception:
                    dead.append(q)
            for q in dead:
                self.clients.discard(q)

stream_manager = StreamManager()
