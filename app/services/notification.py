from typing import Optional, Dict, Any
from datetime import datetime
import uuid

from app.models.notification import Notification
from app.db.session import db

async def create_notification_helper(
    user_id: str,
    title: str,
    message: str,
    notification_type: str = "info",
    action_url: Optional[str] = None,
    metadata: Dict[str, Any] = {}
):
    """Helper function to create notifications for various events"""
    notification_data = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "title": title,
        "message": message,
        "type": notification_type,
        "read": False,
        "action_url": action_url,
        "metadata": metadata,
        "created_at": datetime.utcnow()
    }

    notification_obj = Notification(**notification_data)
    await db.notifications.insert_one(notification_obj.dict())
    return notification_obj

async def notify_all_admins(
    title: str,
    message: str,
    notification_type: str = "info",
    action_url: Optional[str] = None,
    metadata: Dict[str, Any] = {}
):
    """Send notification to all admin users"""
    # Get all admin users
    admin_users = await db.users.find({"role": "admin"}).to_list(100)

    notifications_sent = 0
    for admin in admin_users:
        try:
            await create_notification_helper(
                user_id=admin["id"],
                title=title,
                message=message,
                notification_type=notification_type,
                action_url=action_url,
                metadata=metadata
            )
            notifications_sent += 1
        except Exception as e:
            print(f"Failed to send notification to admin {admin['id']}: {e}")

    return notifications_sent
