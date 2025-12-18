"""
Activity log for tracking webhook events and Linear issue creation.
"""
from datetime import datetime
from collections import deque
from threading import Lock

# Store last 100 activities
_activities = deque(maxlen=100)
_lock = Lock()


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

