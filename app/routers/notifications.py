from fastapi import APIRouter, Depends, HTTPException
from typing import List
from datetime import datetime
import uuid

from app.models.notification import Notification, NotificationCreate
from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user, get_admin_user

router = APIRouter()

@router.get("/notifications", response_model=List[Notification])
async def get_user_notifications(
    limit: int = 50,
    skip: int = 0,
    unread_only: bool = False,
    current_user: User = Depends(get_current_user)
):
    """Get notifications for the current user"""
    query = {"user_id": current_user.id}
    if unread_only:
        query["read"] = False

    notifications = await db.notifications.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [Notification(**notif) for notif in notifications]

@router.get("/notifications/unread-count")
async def get_unread_notifications_count(current_user: User = Depends(get_current_user)):
    """Get count of unread notifications for the current user"""
    count = await db.notifications.count_documents({"user_id": current_user.id, "read": False})
    return {"unread_count": count}

@router.put("/notifications/{notification_id}/mark-read")
async def mark_notification_as_read(
    notification_id: str,
    current_user: User = Depends(get_current_user)
):
    """Mark a notification as read"""
    notification = await db.notifications.find_one({"id": notification_id, "user_id": current_user.id})
    if not notification:
        raise HTTPException(status_code=404, detail="Notification not found")

    if not notification.get("read", False):
        await db.notifications.update_one(
            {"id": notification_id, "user_id": current_user.id},
            {"$set": {"read": True, "read_at": datetime.utcnow()}}
        )

    return {"message": "Notification marked as read"}

@router.put("/notifications/mark-all-read")
async def mark_all_notifications_as_read(current_user: User = Depends(get_current_user)):
    """Mark all notifications as read for the current user"""
    result = await db.notifications.update_many(
        {"user_id": current_user.id, "read": False},
        {"$set": {"read": True, "read_at": datetime.utcnow()}}
    )

    return {"message": f"Marked {result.modified_count} notifications as read"}

@router.post("/notifications", response_model=Notification)
async def create_notification(
    notification_data: NotificationCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new notification (admin only)"""
    notification_dict = notification_data.dict()
    notification_dict["id"] = str(uuid.uuid4())
    notification_dict["created_at"] = datetime.utcnow()

    notification_obj = Notification(**notification_dict)
    await db.notifications.insert_one(notification_obj.dict())

    return notification_obj
