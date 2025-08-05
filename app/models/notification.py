from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import uuid
from datetime import datetime

class Notification(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    message: str
    type: str  # 'success', 'info', 'warning', 'error'
    read: bool = False
    action_url: Optional[str] = None  # URL to navigate to when clicked
    metadata: Dict[str, Any] = {}  # Additional data for the notification
    created_at: datetime = Field(default_factory=datetime.utcnow)
    read_at: Optional[datetime] = None

class NotificationCreate(BaseModel):
    user_id: str
    title: str
    message: str
    type: str = "info"
    action_url: Optional[str] = None
    metadata: Dict[str, Any] = {}
