from datetime import datetime
import logging

from app.db.session import db
from app.services.log import log_activity

logger = logging.getLogger(__name__)

async def check_and_unban_expired_users():
    """Check for temporarily banned users whose ban has expired and unban them"""
    try:
        current_time = datetime.utcnow()
        expired_bans = await db.users.find({
            "status": "banned",
            "ban_type": "temporary",
            "ban_expires_at": {"$lte": current_time}
        }).to_list(100)

        for user in expired_bans:
            # Unban the user
            await db.users.update_one(
                {"id": user["id"]},
                {"$set": {
                    "status": "active",
                    "ban_reason": "",
                    "ban_time": None,
                    "ban_type": None,
                    "ban_expires_at": None
                }}
            )

            # Log the automatic unban
            await log_activity(
                user_id="system",
                username="system",
                action="auto_unban",
                details=f"Automatically unbanned user {user['username']} after temporary ban expired",
                target_id=user["id"],
                target_type="user"
            )

        return len(expired_bans)
    except Exception as e:
        logger.error(f"Failed to check expired bans: {str(e)}")
        return 0
