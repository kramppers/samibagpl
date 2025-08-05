from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime

class TicketAttachment(BaseModel):
    filename: str
    file_data: str  # base64 encoded file data
    file_type: str
    file_size: int

class TicketActivity(BaseModel):
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    actor: str  # username of who performed the action
    action: str  # 'created', 'status_changed', 'response_added', 'attachment_added'
    details: str
    old_value: Optional[str] = None
    new_value: Optional[str] = None

class Ticket(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    email: str
    ticket_type: str  # general, payment_problem, account_deletion, technical_issue, billing, other
    priority: str  # low, medium, high, critical
    subject: str
    description: str
    status: str = "open"  # open, in_progress, resolved, closed, reopened
    admin_response: Optional[str] = ""
    assigned_to: Optional[str] = None  # Admin user ID
    assigned_to_name: Optional[str] = None
    tags: List[str] = []  # Custom tags for better organization
    attachments: List[TicketAttachment] = []
    activity_history: List[TicketActivity] = []
    satisfaction_rating: Optional[int] = None  # 1-5 rating after resolution
    satisfaction_feedback: Optional[str] = None
    estimated_resolution_time: Optional[str] = None
    category: Optional[str] = None  # Different from ticket_type - for better categorization
    severity: Optional[str] = "normal"  # normal, high, critical
    first_response_time: Optional[datetime] = None
    resolution_time: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None

class TicketCreate(BaseModel):
    ticket_type: str
    priority: str
    subject: str
    description: str
    attachments: Optional[List[TicketAttachment]] = []
    tags: Optional[List[str]] = []
    category: Optional[str] = None
    severity: Optional[str] = "normal"

class TicketUpdate(BaseModel):
    status: Optional[str] = None
    admin_response: Optional[str] = None
    assigned_to: Optional[str] = None
    assigned_to_name: Optional[str] = None
    tags: Optional[List[str]] = None
    category: Optional[str] = None
    severity: Optional[str] = None
    estimated_resolution_time: Optional[str] = None

class KnowledgeBaseArticle(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content: str
    summary: str
    category: str
    tags: List[str] = []
    helpful_votes: int = 0
    not_helpful_votes: int = 0
    views: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None
    author: str  # Admin username
    status: str = "published"  # draft, published, archived

class TicketTemplate(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    ticket_type: str
    priority: str
    subject_template: str
    description_template: str
    suggested_tags: List[str] = []
    category: Optional[str] = None
