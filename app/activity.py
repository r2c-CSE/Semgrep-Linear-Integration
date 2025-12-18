"""
Activity log for tracking webhook events and Linear issue creation.
Supports in-memory storage with optional file persistence.
"""
import json
import os
import logging
from datetime import datetime
from collections import deque
from threading import Lock
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Store last 500 activities in memory
_activities = deque(maxlen=500)
_lock = Lock()
_log_file: Optional[Path] = None
_max_file_size_bytes: int = 10 * 1024 * 1024  # 10MB default


def configure(log_file: str = "", max_size_mb: int = 10):
    """
    Configure activity log persistence.
    
    Args:
        log_file: Path to activity log file (empty = memory only)
        max_size_mb: Maximum log file size before rotation
    """
    global _log_file, _max_file_size_bytes
    
    if log_file:
        _log_file = Path(log_file)
        _max_file_size_bytes = max_size_mb * 1024 * 1024
        
        # Ensure directory exists
        _log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Load existing activities from file
        _load_from_file()
        
        logger.info(f"Activity log persistence enabled: {log_file}")
    else:
        _log_file = None


def _load_from_file():
    """Load existing activities from the log file."""
    global _activities
    
    if not _log_file or not _log_file.exists():
        return
    
    try:
        with open(_log_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        activity = json.loads(line)
                        _activities.append(activity)
                    except json.JSONDecodeError:
                        continue
        
        # Convert to deque with maxlen (keeps most recent)
        _activities = deque(list(_activities)[-500:], maxlen=500)
        logger.info(f"Loaded {len(_activities)} activities from file")
        
    except Exception as e:
        logger.error(f"Error loading activity log: {e}")


def _write_to_file(activity: dict):
    """Write activity to log file with rotation."""
    if not _log_file:
        return
    
    try:
        # Check file size and rotate if needed
        if _log_file.exists() and _log_file.stat().st_size > _max_file_size_bytes:
            _rotate_log_file()
        
        # Append activity
        with open(_log_file, "a") as f:
            f.write(json.dumps(activity) + "\n")
            
    except Exception as e:
        logger.error(f"Error writing to activity log: {e}")


def _rotate_log_file():
    """Rotate the log file (keep .1 backup)."""
    if not _log_file:
        return
    
    try:
        backup_path = _log_file.with_suffix(_log_file.suffix + ".1")
        
        # Remove old backup
        if backup_path.exists():
            backup_path.unlink()
        
        # Rename current to backup
        if _log_file.exists():
            _log_file.rename(backup_path)
        
        logger.info(f"Rotated activity log file")
        
    except Exception as e:
        logger.error(f"Error rotating activity log: {e}")


def log_activity(event_type: str, message: str, details: dict = None, status: str = "info"):
    """
    Log an activity event.
    
    Args:
        event_type: Type of event (webhook_received, issue_created, error, etc.)
        message: Human-readable message
        details: Additional details dict
        status: success, error, warning, info
    """
    activity = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "type": event_type,
        "message": message,
        "details": details or {},
        "status": status
    }
    
    with _lock:
        _activities.appendleft(activity)
        _write_to_file(activity)


def get_activities(limit: int = 50) -> list:
    """Get recent activities."""
    with _lock:
        return list(_activities)[:limit]


def get_stats() -> dict:
    """Get activity statistics."""
    with _lock:
        activities = list(_activities)
    
    total = len(activities)
    success = sum(1 for a in activities if a["status"] == "success")
    errors = sum(1 for a in activities if a["status"] == "error")
    
    # Count by type
    by_type = {}
    for a in activities:
        t = a["type"]
        by_type[t] = by_type.get(t, 0) + 1
    
    return {
        "total": total,
        "success": success,
        "errors": errors,
        "by_type": by_type
    }


def get_metrics() -> dict:
    """Get metrics for monitoring (Prometheus-style)."""
    stats = get_stats()
    
    return {
        "semgrep_linear_activities_total": stats["total"],
        "semgrep_linear_issues_created_total": stats["by_type"].get("issue_created", 0),
        "semgrep_linear_issues_skipped_total": stats["by_type"].get("issue_skipped", 0),
        "semgrep_linear_webhooks_received_total": stats["by_type"].get("webhook_received", 0),
        "semgrep_linear_errors_total": stats["errors"],
    }
