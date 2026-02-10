import time
import asyncio

class RateLimiter:
    """Simple rate limiter for API calls and tool execution."""

    def __init__(self, max_calls: int = 5, period: int = 1):
        self.max_calls = max_calls
        self.period = period
        self.timestamps = []

    async def wait(self) -> None:
        """Wait if rate limit is exceeded."""
        now = time.time()
        self.timestamps = [t for t in self.timestamps if t > now - self.period]
        if len(self.timestamps) >= self.max_calls:
            sleep_time = self.period - (now - self.timestamps[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
        self.timestamps.append(time.time())