from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import uuid
from datetime import datetime

# Authentication models
class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class UserProfileUpdate(BaseModel):
    bio: Optional[str] = None
    website: Optional[str] = None
    github: Optional[str] = None
    linkedin: Optional[str] = None
    twitter: Optional[str] = None
    skills: Optional[List[str]] = None
    location: Optional[str] = None

class CustomRole(BaseModel):
    name: str
    icon: str
    color: str

class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    user_type: str = "buyer"
    role: str = "user"  # user, admin
    custom_role: Optional[CustomRole] = None  # Additional custom role for display
    status: str = "active"  # active, banned, pending_deletion
    deletion_request_id: Optional[str] = None  # Reference to deletion request, pending_deletion
    deletion_request_id: Optional[str] = None  # Reference to deletion request
    ban_reason: Optional[str] = ""
    ban_time: Optional[datetime] = None
    ban_type: Optional[str] = None  # permanent, temporary
    ban_expires_at: Optional[datetime] = None
    admin_notes: Optional[str] = ""  # Admin-only notes about the user
    bookmarked_products: List[str] = []  # List of bookmarked product IDs
    bookmarked_sellers: List[str] = []   # List of bookmarked seller IDs
    bio: Optional[str] = ""
    website: Optional[str] = ""
    github: Optional[str] = ""
    linkedin: Optional[str] = ""
    twitter: Optional[str] = ""
    skills: List[str] = []
    location: Optional[str] = ""
    avatar: Optional[str] = ""
    total_sales: int = 0
    total_purchases: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DeletionRequest(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    email: str
    reason: str
    status: str = "pending"  # pending, approved, rejected
    admin_response: Optional[str] = ""
    processed_by: Optional[str] = None  # admin user ID
    processed_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class PublicProfile(BaseModel):
    id: str
    username: str
    user_type: str
    role: str = "user"
    custom_role: Optional[CustomRole] = None
    status: str = "active"
    ban_reason: Optional[str] = ""
    ban_time: Optional[datetime] = None
    ban_type: Optional[str] = None
    ban_expires_at: Optional[datetime] = None
    admin_notes: Optional[str] = ""  # Will be filtered out for non-admin users
    bio: Optional[str] = ""
    website: Optional[str] = ""
    github: Optional[str] = ""
    linkedin: Optional[str] = ""
    twitter: Optional[str] = ""
    skills: List[str] = []
    location: Optional[str] = ""
    avatar: Optional[str] = ""
    total_sales: int = 0
    total_purchases: int = 0
    created_at: datetime

class Token(BaseModel):
    access_token: str
    token_type: str

# Role management models
class CustomRoleTemplate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    icon: str
    color: str
    created_by: str  # admin who created it
    created_at: datetime = Field(default_factory=datetime.utcnow)

class CustomRoleCreate(BaseModel):
    name: str
    icon: str
    color: str

class UserTypeUpdate(BaseModel):
    user_type: str  # buyer, seller

class AssignCustomRole(BaseModel):
    role_name: str
    icon: str
    color: str

class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str

class EmailChangeRequest(BaseModel):
    new_email: str
    password: str

class ProfileComment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    profile_id: str  # User ID of the profile being commented on
    author_id: str   # User ID of the comment author
    author_username: str
    author_avatar: Optional[str] = ""
    content: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None

class ProfileCommentCreate(BaseModel):
    profile_id: str
    content: str
