from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

class ActivityLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    action: str  # 'product_created', 'seller_application', 'password_changed', 'profile_updated', 'comment_posted', etc.
    details: str  # Human-readable description of the action
    target_id: Optional[str] = None  # ID of the target entity (product_id, application_id, etc.)
    target_type: Optional[str] = None  # 'product', 'application', 'profile', 'comment', etc.
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
