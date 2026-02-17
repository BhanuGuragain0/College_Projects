"""
SecureComm Performance Metrics Collection
Tracks operation latencies, error rates, and throughput

Author: SecureComm Team
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from threading import Lock
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class Metric:
    """Represents a single metric value"""

    def __init__(self, name: str, value: float, unit: str = "ms", timestamp: Optional[datetime] = None):
        self.name = name
        self.value = value
        self.unit = unit
        self.timestamp = timestamp or datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "value": self.value,
            "unit": self.unit,
            "timestamp": self.timestamp.isoformat(),
        }


class MetricsCollector:
    """Collects and aggregates performance metrics"""

    def __init__(self, window_size: int = 3600):
        """
        Initialize metrics collector
        
        Args:
            window_size: Time window for metrics (seconds), default 1 hour
        """
        self._lock = Lock()
        self._window_size = window_size
        
        # Metrics storage
        self._operation_times: Dict[str, List[float]] = defaultdict(list)
        self._error_counts: Dict[str, int] = defaultdict(int)
        self._operation_counts: Dict[str, int] = defaultdict(int)
        self._timestamps: Dict[str, List[datetime]] = defaultdict(list)

    @contextmanager
    def measure(self, operation_name: str):
        """
        Context manager to measure operation latency
        
        Usage:
            with metrics.measure("certificate_validation") as ctx:
                validate_certificate(cert)
                # Latency automatically recorded
        """
        start = time.time()
        try:
            yield self
        finally:
            elapsed = (time.time() - start) * 1000  # ms
            self.record_metric(operation_name, elapsed)

    def record_metric(self, operation_name: str, latency_ms: float):
        """Record operation latency"""
        with self._lock:
            now = datetime.now(timezone.utc)
            
            # Add metric
            self._operation_times[operation_name].append(latency_ms)
            self._timestamps[operation_name].append(now)
            self._operation_counts[operation_name] += 1
            
            # Cleanup old metrics
            self._cleanup_old_metrics(operation_name, now)

    def record_error(self, error_type: str):
        """Record operation error"""
        with self._lock:
            self._error_counts[error_type] += 1

    def get_operation_stats(self, operation_name: str) -> Dict[str, Any]:
        """Get statistics for an operation"""
        with self._lock:
            times = self._operation_times.get(operation_name, [])
            if not times:
                return {
                    "operation": operation_name,
                    "count": 0,
                    "min_ms": 0,
                    "max_ms": 0,
                    "avg_ms": 0,
                    "p50_ms": 0,
                    "p95_ms": 0,
                    "p99_ms": 0,
                }
            
            times_sorted = sorted(times)
            n = len(times_sorted)
            
            return {
                "operation": operation_name,
                "count": len(times),
                "min_ms": min(times),
                "max_ms": max(times),
                "avg_ms": sum(times) / len(times),
                "p50_ms": times_sorted[int(n * 0.50)],
                "p95_ms": times_sorted[int(n * 0.95)],
                "p99_ms": times_sorted[int(n * 0.99)],
            }

    def get_all_stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all operations"""
        with self._lock:
            return {
                op_name: self.get_operation_stats(op_name)
                for op_name in self._operation_times.keys()
            }

    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        with self._lock:
            total_errors = sum(self._error_counts.values())
            return {
                "total_errors": total_errors,
                "error_types": dict(self._error_counts),
                "errors_per_minute": total_errors / (self._window_size / 60),
            }

    def get_throughput(self, operation_name: str) -> Dict[str, float]:
        """Get throughput statistics (operations per second)"""
        with self._lock:
            count = self._operation_counts.get(operation_name, 0)
            ops_per_second = count / (self._window_size / 1000)
            
            return {
                "operation": operation_name,
                "count": count,
                "ops_per_second": ops_per_second,
                "window_seconds": self._window_size,
            }

    def get_all_metrics(self) -> Dict[str, Any]:
        """Get all metrics for reporting"""
        with self._lock:
            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "window_seconds": self._window_size,
                "operations": self.get_all_stats(),
                "errors": self.get_error_stats(),
                "throughput": {
                    op: self.get_throughput(op)
                    for op in self._operation_counts.keys()
                },
            }

    def reset(self):
        """Reset all metrics"""
        with self._lock:
            self._operation_times.clear()
            self._error_counts.clear()
            self._operation_counts.clear()
            self._timestamps.clear()

    def _cleanup_old_metrics(self, operation_name: str, now: datetime):
        """Remove metrics outside the time window"""
        cutoff = now - timedelta(seconds=self._window_size)
        
        times = self._operation_times.get(operation_name, [])
        timestamps = self._timestamps.get(operation_name, [])
        
        if timestamps:
            # Find first timestamp within window
            valid_idx = 0
            for i, ts in enumerate(timestamps):
                if ts >= cutoff:
                    valid_idx = i
                    break
            
            # Trim to valid range
            if valid_idx > 0:
                self._operation_times[operation_name] = times[valid_idx:]
                self._timestamps[operation_name] = timestamps[valid_idx:]


# Global metrics instance
_global_metrics = MetricsCollector()


def get_metrics() -> MetricsCollector:
    """Get global metrics collector instance"""
    return _global_metrics
