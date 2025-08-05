from fastapi import Request
from typing import Optional
import logging

from app.models.log import ActivityLog
from app.db.session import db

logger = logging.getLogger(__name__)

async def log_activity(
    user_id: str,
    username: str,
    action: str,
    details: str,
    target_id: Optional[str] = None,
    target_type: Optional[str] = None,
    request: Optional[Request] = None
):
    """Log user activity for admin monitoring"""
    try:
        log_data = {
            "user_id": user_id,
            "username": username,
            "action": action,
            "details": details,
            "target_id": target_id,
            "target_type": target_type,
        }

        if request:
            # Get IP address (handle proxy headers)
            ip = request.headers.get("x-forwarded-for")
            if ip:
                ip = ip.split(',')[0].strip()
            else:
                ip = request.client.host if request.client else "unknown"

            log_data["ip_address"] = ip
            log_data["user_agent"] = request.headers.get("user-agent", "unknown")

        activity_log = ActivityLog(**log_data)
        await db.activity_logs.insert_one(activity_log.dict())
    except Exception as e:
        # Don't fail the main operation if logging fails
        logger.error(f"Failed to log activity: {str(e)}")
