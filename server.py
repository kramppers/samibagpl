from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Form, Request, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse, StreamingResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any, Union
import uuid
from datetime import datetime, timedelta
import hashlib
import shutil
import json
import unicodedata
import re
import base64
from io import BytesIO

# Stripe integration

# Authentication
import bcrypt
from jose import JWTError, jwt

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# File storage configuration
UPLOAD_DIR = Path("/app/uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

def sanitize_filename(filename: str, max_length: int = 100) -> str:
    """
    Sanitize filename to be safe across different operating systems.
    Removes invalid characters, normalizes unicode, and limits length.
    Enhanced for Windows zip file compatibility.
    """
    if not filename:
        return "download"
    
    # Normalize unicode characters
    filename = unicodedata.normalize('NFKD', filename)
    
    # Remove non-ASCII characters that might cause issues
    filename = filename.encode('ascii', 'ignore').decode('ascii')
    
    # Remove or replace invalid characters for Windows/Mac/Linux
    # Invalid chars: < > : " | ? * \ / and control characters
    invalid_chars = r'[<>:"|?*\\/-\x00-\x1f\x7f]'
    filename = re.sub(invalid_chars, '_', filename)
    
    # Remove problematic Windows reserved names
    reserved_names = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 
                      'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 
                      'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9']
    
    name_part = filename.split('.')[0] if '.' in filename else filename
    if name_part.upper() in reserved_names:
        filename = f"file_{filename}"
    
    # Remove leading/trailing spaces and dots (Windows issue)
    filename = filename.strip('. ')
    
    # Replace multiple spaces/underscores with single ones
    filename = re.sub(r'[_\s]+', '_', filename)
    
    # Ensure it doesn't start with special characters
    filename = re.sub(r'^[._-]+', '', filename)
    
    # Remove any remaining problematic sequences
    filename = re.sub(r'__+', '_', filename)  # Multiple underscores
    filename = re.sub(r'\.\.+', '.', filename)  # Multiple dots
    
    # Limit length while preserving extension
    if len(filename) > max_length:
        name_part, ext_part = os.path.splitext(filename)
        max_name_length = max_length - len(ext_part)
        if max_name_length > 0:
            filename = name_part[:max_name_length] + ext_part
        else:
            filename = filename[:max_length]
    
    # Final cleanup - ensure no trailing dots or spaces (Windows)
    filename = filename.rstrip('. ')
    
    # Fallback if empty
    if not filename or filename in ['', '.', '_']:
        return "download"
    
    return filename


def get_media_type_for_file(file_extension: str) -> str:
    """
    Get appropriate media type based on file extension.
    Returns proper MIME type for common file types.
    """
    # Normalize extension to lowercase
    ext = file_extension.lower()
    
    # Common media types mapping
    media_types = {
        # Documents
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'txt': 'text/plain',
        'rtf': 'application/rtf',
        
        # Images
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'bmp': 'image/bmp',
        'svg': 'image/svg+xml',
        'webp': 'image/webp',
        
        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        'm4a': 'audio/mp4',
        
        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'wmv': 'video/x-ms-wmv',
        'flv': 'video/x-flv',
        'webm': 'video/webm',
        
        # Archives
        'zip': 'application/zip',
        'rar': 'application/vnd.rar',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        
        # Code files
        'js': 'application/javascript',
        'css': 'text/css',
        'html': 'text/html',
        'xml': 'application/xml',
        'json': 'application/json',
        'py': 'text/x-python',
        'java': 'text/x-java-source',
        'cpp': 'text/x-c++src',
        'c': 'text/x-csrc',
        'php': 'application/x-httpd-php',
        
        # Other common types
        'exe': 'application/vnd.microsoft.portable-executable',
        'dmg': 'application/x-apple-diskimage',
        'iso': 'application/x-iso9660-image',
    }
    
    return media_types.get(ext, 'application/octet-stream')

# Stripe configuration
stripe_api_key = os.environ.get('STRIPE_API_KEY')

# Import StripeCheckout from your Stripe integration module
# Make sure you have a file like stripe_checkout.py or similar with StripeCheckout defined
try:
    from stripe_checkout import StripeCheckout, CheckoutSessionRequest
except ImportError:
    # If you don't have a module, define a placeholder or raise an error
    class StripeCheckout:
        def __init__(self, api_key, webhook_url):
            raise NotImplementedError("StripeCheckout class must be implemented or imported from your Stripe integration module.")

    class CheckoutSessionRequest:
        def __init__(self, amount, currency, success_url, cancel_url, metadata):
            pass

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

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

# Product models
class Product(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    description: str
    price: float
    category: str
    seller_id: str
    seller_name: str
    file_name: str
    original_filename: Optional[str] = ""  # Store original uploaded filename
    file_size: int
    image: Optional[str] = ""  # Base64 encoded image
    rating_average: float = 0.0
    rating_count: int = 0
    status: str = "pending"  # pending, approved, rejected
    rejection_reason: Optional[str] = ""  # Reason when product is rejected
    created_at: datetime = Field(default_factory=datetime.utcnow)
    downloads: int = 0

class ProductCreate(BaseModel):
    title: str
    description: str
    price: float
    category: str

class ProductEdit(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    price: Optional[float] = None
    category: Optional[str] = None
    status: Optional[str] = None

class ProductStatusUpdate(BaseModel):
    status: str  # pending, approved, rejected
    rejection_reason: Optional[str] = None  # Required when status is rejected

class Rating(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    product_id: str
    user_id: str
    username: str
    rating: int = Field(..., ge=1, le=5)  # 1-5 stars
    review: Optional[str] = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)

class RatingCreate(BaseModel):
    product_id: str
    rating: int = Field(..., ge=1, le=5)
    review: Optional[str] = ""

# Seller Application models
class SellerApplication(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    email: str
    answers: Dict[str, Union[str, List[str]]] = {}  # Dynamic answers based on questions
    business_name: Optional[str] = ""
    business_description: Optional[str] = ""  # Made optional for backward compatibility
    experience_years: Optional[int] = 0  # Made optional for backward compatibility
    portfolio_url: Optional[str] = ""
    why_sell: Optional[str] = ""  # Made optional for backward compatibility
    product_types: List[str] = []
    previous_platforms: Optional[str] = ""
    status: str = "pending"  # pending, approved, rejected
    admin_notes: Optional[str] = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    reviewed_at: Optional[datetime] = None
    reviewed_by: Optional[str] = None

class SellerApplicationCreate(BaseModel):
    answers: Dict[str, Union[str, List[str]]] = {}  # Dynamic answers based on questions

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

class QuestionReorderRequest(BaseModel):
    question_ids: List[str]

class SellerApplicationQuestion(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    question: str
    question_type: str = "text"  # text, textarea, select, checkbox
    options: List[str] = []  # For select/checkbox types
    required: bool = True
    order: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SellerApplicationQuestionCreate(BaseModel):
    question: str
    question_type: str = "text"
    options: List[str] = []
    required: bool = True

class SellerApplicationQuestionUpdate(BaseModel):
    question: Optional[str] = None
    question_type: Optional[str] = None
    options: Optional[List[str]] = None
    required: Optional[bool] = None
    order: Optional[int] = None

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

class RatingResponse(BaseModel):
    rating: Rating
    can_edit: bool = False

# Payment models
class PaymentTransaction(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    session_id: str
    product_id: str
    buyer_id: str
    seller_id: str
    amount: float
    currency: str = "usd"
    payment_status: str = "pending"
    stripe_status: str = "initiated"
    metadata: Dict[str, Any] = {}
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class Purchase(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    buyer_id: str
    product_id: str
    seller_id: str
    transaction_id: str
    download_token: str
    purchased_at: datetime = Field(default_factory=datetime.utcnow)

class DebugPurchaseRequest(BaseModel):
    product_id: str
    buyer_id: Optional[str] = None  # Optional - if not provided, uses admin as buyer

# Security functions
security = HTTPBearer(auto_error=False)
oauth2_scheme_optional = HTTPBearer(auto_error=False)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        
        user = await db.users.find_one({"id": user_id})
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Check if user is banned
        if user.get("status") == "banned":
            raise HTTPException(status_code=403, detail="User is banned")
        
        return User(**user)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    if credentials is None:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if user_id is None:
            return None
        
        user = await db.users.find_one({"id": user_id})
        if user is None:
            return None
        
        # Check if user is banned
        if user.get("status") == "banned":
            return None
        
        return User(**user)
    except JWTError:
        return None

# Helper function for optional current user (allows unauthenticated requests)
async def get_current_user_optional_new(credentials: Optional[HTTPAuthorizationCredentials] = Depends(oauth2_scheme_optional)):
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            return None
    except JWTError:
        return None
    
    user = await db.users.find_one({"id": user_id})
    if user is None:
        return None
    
    return User(**user)

async def get_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

async def update_product_rating(product_id: str):
    """Update product's average rating and count"""
    ratings = await db.ratings.find({"product_id": product_id}).to_list(1000)
    if ratings:
        total_rating = sum(r["rating"] for r in ratings)
        average_rating = total_rating / len(ratings)
        rating_count = len(ratings)
    else:
        average_rating = 0.0
        rating_count = 0
    
    await db.products.update_one(
        {"id": product_id},
        {"$set": {"rating_average": round(average_rating, 1), "rating_count": rating_count}}
    )

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

# Authentication endpoints
@api_router.post("/auth/register", response_model=Token)
async def register(user_data: UserCreate):
    existing_user = await db.users.find_one({"$or": [{"email": user_data.email}, {"username": user_data.username}]})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = hash_password(user_data.password)
    user_dict = user_data.dict()
    user_dict.pop("password")
    user_dict["hashed_password"] = hashed_password
    user_dict["user_type"] = "buyer"  # Default to buyer
    
    user_obj = User(**{k: v for k, v in user_dict.items() if k != "hashed_password"})
    user_doc = user_obj.dict()
    user_doc["hashed_password"] = hashed_password
    await db.users.insert_one(user_doc)
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_obj.id}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user = await db.users.find_one({"email": user_data.email})
    if not user or not verify_password(user_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["id"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@api_router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@api_router.put("/profile", response_model=User)
async def update_profile(
    request: Request,
    profile_data: UserProfileUpdate,
    current_user: User = Depends(get_current_user)
):
    update_data = {k: v for k, v in profile_data.dict().items() if v is not None}
    if update_data:
        update_data["updated_at"] = datetime.utcnow()
        await db.users.update_one(
            {"id": current_user.id},
            {"$set": update_data}
        )
        
        # Log activity
        updated_fields = list(update_data.keys())
        updated_fields.remove("updated_at")  # Don't include timestamp in details
        await log_activity(
            user_id=current_user.id,
            username=current_user.username,
            action="profile_updated",
            details=f"Updated profile fields: {', '.join(updated_fields)}",
            target_type="profile",
            request=request
        )
        
        # Fetch updated user
        updated_user = await db.users.find_one({"id": current_user.id})
        return User(**updated_user)
    
    return current_user

@api_router.post("/profile/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")
    
    # Save avatar file
    file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
    avatar_filename = f"avatar_{current_user.id}.{file_extension}"
    avatar_path = UPLOAD_DIR / "avatars"
    avatar_path.mkdir(exist_ok=True)
    full_avatar_path = avatar_path / avatar_filename
    
    with open(full_avatar_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Convert to base64 for storage
    with open(full_avatar_path, "rb") as img_file:
        avatar_base64 = base64.b64encode(img_file.read()).decode('utf-8')
        avatar_data_url = f"data:{file.content_type};base64,{avatar_base64}"
    
    # Update user avatar in database
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"avatar": avatar_data_url, "updated_at": datetime.utcnow()}}
    )
    
    # Clean up file
    os.unlink(full_avatar_path)
    
    return {"avatar": avatar_data_url}

@api_router.get("/profile/{user_id}", response_model=PublicProfile)
async def get_public_profile(
    user_id: str, 
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if temporary ban has expired
    if (user.get("status") == "banned" and 
        user.get("ban_type") == "temporary" and 
        user.get("ban_expires_at") and 
        datetime.utcnow() > user["ban_expires_at"]):
        
        # Automatically unban expired user
        await db.users.update_one(
            {"id": user_id},
            {"$set": {
                "status": "active",
                "ban_reason": "",
                "ban_time": None,
                "ban_type": None,
                "ban_expires_at": None
            }}
        )
        # Refresh user data
        user = await db.users.find_one({"id": user_id})
    
    # Get sales/purchase counts
    if user["user_type"] == "seller":
        sales_count = await db.products.count_documents({"seller_id": user_id})
        user["total_sales"] = sales_count
    
    purchases_count = await db.purchases.count_documents({"buyer_id": user_id})
    user["total_purchases"] = purchases_count
    
    # Remove sensitive data for public profile
    exclude_fields = ["email", "hashed_password"]
    
    # Hide admin notes from non-admin users
    if not current_user or current_user.role != "admin":
        exclude_fields.append("admin_notes")
    
    public_data = {k: v for k, v in user.items() if k not in exclude_fields}
    return PublicProfile(**public_data)

@api_router.get("/sellers", response_model=List[PublicProfile])
async def get_sellers(current_user: Optional[User] = Depends(get_current_user_optional)):
    sellers = await db.users.find({"user_type": "seller"}).to_list(50)
    result = []
    
    for seller in sellers:
        # Get sales count
        sales_count = await db.products.count_documents({"seller_id": seller["id"]})
        seller["total_sales"] = sales_count
        
        # Remove sensitive data
        exclude_fields = ["email", "hashed_password"]
        
        # Hide admin notes from non-admin users
        if not current_user or current_user.role != "admin":
            exclude_fields.append("admin_notes")
        
        public_data = {k: v for k, v in seller.items() if k not in exclude_fields}
        result.append(PublicProfile(**public_data))
    
    return result

# New endpoints for enhanced features
@api_router.get("/profiles", response_model=List[PublicProfile])
async def get_all_profiles(
    search: Optional[str] = None,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    query = {}
    if search:
        query["$or"] = [
            {"username": {"$regex": search, "$options": "i"}},
            {"bio": {"$regex": search, "$options": "i"}},
            {"skills": {"$regex": search, "$options": "i"}}
        ]
    
    users = await db.users.find(query).to_list(100)
    result = []
    
    for user in users:
        # Get user stats
        if user["user_type"] == "seller":
            sales_count = await db.products.count_documents({"seller_id": user["id"]})
            user["total_sales"] = sales_count
        else:
            user["total_sales"] = 0
        
        purchases_count = await db.purchases.count_documents({"buyer_id": user["id"]})
        user["total_purchases"] = purchases_count
        
        # Remove sensitive data
        exclude_fields = ["email", "hashed_password"]
        
        # Hide admin notes from non-admin users
        if not current_user or current_user.role != "admin":
            exclude_fields.append("admin_notes")
        
        public_data = {k: v for k, v in user.items() if k not in exclude_fields}
        result.append(PublicProfile(**public_data))
    
    return result

@api_router.get("/profile/{user_id}/purchases")
async def get_user_public_purchases(user_id: str):
    purchases = await db.purchases.find({"buyer_id": user_id}).to_list(100)
    
    result = []
    for purchase in purchases:
        product = await db.products.find_one({"id": purchase["product_id"]})
        if product:
            result.append({
                "product_title": product["title"],
                "product_category": product["category"],
                "seller_name": product["seller_name"],
                "purchased_at": purchase["purchased_at"],
                "price": product["price"]
            })
    
    return result

@api_router.put("/settings/password")
async def change_password(
    request: Request,
    password_data: PasswordChangeRequest,
    current_user: User = Depends(get_current_user)
):
    # Verify current password
    user_doc = await db.users.find_one({"id": current_user.id})
    if not verify_password(password_data.current_password, user_doc["hashed_password"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    # Hash new password
    new_hashed_password = hash_password(password_data.new_password)
    
    # Update password
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"hashed_password": new_hashed_password}}
    )
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="password_changed",
        details="User changed their password",
        target_type="profile",
        request=request
    )
    
    return {"message": "Password updated successfully"}

@api_router.put("/settings/email")
async def change_email(
    request: Request,
    email_data: EmailChangeRequest,
    current_user: User = Depends(get_current_user)
):
    # Verify password
    user_doc = await db.users.find_one({"id": current_user.id})
    if not verify_password(email_data.password, user_doc["hashed_password"]):
        raise HTTPException(status_code=400, detail="Password is incorrect")
    
    # Check if email already exists
    existing_user = await db.users.find_one({"email": email_data.new_email})
    if existing_user and existing_user["id"] != current_user.id:
        raise HTTPException(status_code=400, detail="Email already in use")
    
    # Update email
    await db.users.update_one(
        {"id": current_user.id},
        {"$set": {"email": email_data.new_email}}
    )
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="email_changed",
        details=f"Changed email to {email_data.new_email}",
        target_type="profile",
        request=request
    )
    
    return {"message": "Email updated successfully"}

# Profile Comments endpoints
@api_router.post("/profile-comments", response_model=ProfileComment)
async def create_profile_comment(
    request: Request,
    comment_data: ProfileCommentCreate,
    current_user: User = Depends(get_current_user)
):
    # Check if the profile exists
    profile_user = await db.users.find_one({"id": comment_data.profile_id})
    if not profile_user:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Create comment
    comment_dict = comment_data.dict()
    comment_dict["author_id"] = current_user.id
    comment_dict["author_username"] = current_user.username
    comment_dict["author_avatar"] = current_user.avatar or ""
    
    comment_obj = ProfileComment(**comment_dict)
    await db.profile_comments.insert_one(comment_obj.dict())
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="comment_posted",
        details=f"Posted comment on {profile_user['username']}'s profile",
        target_id=comment_obj.id,
        target_type="comment",
        request=request
    )
    
    return comment_obj

@api_router.get("/profile-comments/{profile_id}", response_model=List[ProfileComment])
async def get_profile_comments(profile_id: str):
    # Check if the profile exists
    profile_user = await db.users.find_one({"id": profile_id})
    if not profile_user:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    comments = await db.profile_comments.find({"profile_id": profile_id}).sort("created_at", -1).to_list(100)
    return [ProfileComment(**comment) for comment in comments]

@api_router.put("/profile-comments/{comment_id}", response_model=ProfileComment)
async def update_profile_comment(
    comment_id: str,
    content: str,
    current_user: User = Depends(get_current_user)
):
    # Find the comment
    comment = await db.profile_comments.find_one({"id": comment_id})
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Check if the user is the author
    if comment["author_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own comments")
    
    # Update comment
    update_data = {
        "content": content,
        "updated_at": datetime.utcnow()
    }
    
    await db.profile_comments.update_one({"id": comment_id}, {"$set": update_data})
    
    # Return updated comment
    updated_comment = await db.profile_comments.find_one({"id": comment_id})
    return ProfileComment(**updated_comment)

@api_router.delete("/profile-comments/{comment_id}")
async def delete_profile_comment(
    comment_id: str,
    current_user: User = Depends(get_current_user)
):
    # Find the comment
    comment = await db.profile_comments.find_one({"id": comment_id})
    if not comment:
        raise HTTPException(status_code=404, detail="Comment not found")
    
    # Check if the user is the author or admin
    if comment["author_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You can only delete your own comments or need admin access")
    
    # Delete comment
    await db.profile_comments.delete_one({"id": comment_id})
    
    return {"message": "Comment deleted successfully"}

# Admin Logs endpoints
@api_router.get("/admin/logs", response_model=List[ActivityLog])
async def get_activity_logs(
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    target_type: Optional[str] = None,
    limit: int = Query(100, le=1000),
    skip: int = Query(0, ge=0),
    admin_user: User = Depends(get_admin_user)
):
    """Get activity logs with optional filtering"""
    query = {}
    
    if action:
        query["action"] = action
    if user_id:
        query["user_id"] = user_id
    if username:
        query["username"] = {"$regex": username, "$options": "i"}
    if target_type:
        query["target_type"] = target_type
    
    logs = await db.activity_logs.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [ActivityLog(**log) for log in logs]

@api_router.get("/admin/logs/stats")
async def get_logs_stats(admin_user: User = Depends(get_admin_user)):
    """Get statistics about activity logs"""
    pipeline = [
        {
            "$group": {
                "_id": "$action",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]
    
    stats = await db.activity_logs.aggregate(pipeline).to_list(100)
    total_logs = await db.activity_logs.count_documents({})
    
    return {
        "total_logs": total_logs,
        "action_stats": stats
    }

@api_router.get("/admin/users/search")
async def search_users(
    query: str = Query(..., min_length=1),
    limit: int = Query(20, le=100),
    admin_user: User = Depends(get_admin_user)
):
    """Search users by username or email"""
    search_query = {
        "$or": [
            {"username": {"$regex": query, "$options": "i"}},
            {"email": {"$regex": query, "$options": "i"}}
        ]
    }
    
    users = await db.users.find(search_query).limit(limit).to_list(limit)
    
    # Remove sensitive data and MongoDB ObjectId
    safe_users = []
    for user in users:
        safe_user = {k: v for k, v in user.items() if k not in ["hashed_password", "_id"]}
        safe_users.append(safe_user)
    
    return safe_users

# Seller Application Questions Management
@api_router.get("/seller-application-questions", response_model=List[SellerApplicationQuestion])
async def get_seller_application_questions():
    """Get all seller application questions"""
    questions = await db.seller_questions.find({}).sort("order", 1).to_list(100)
    if not questions:
        # Create default questions if none exist
        default_questions = [
            {
                "question": "What programming languages are you proficient in?",
                "question_type": "textarea",
                "required": True,
                "order": 1
            },
            {
                "question": "How many years of experience do you have in software development?",
                "question_type": "select",
                "options": ["Less than 1 year", "1-2 years", "3-5 years", "6-10 years", "More than 10 years"],
                "required": True,
                "order": 2
            },
            {
                "question": "Tell us about your most significant project or accomplishment.",
                "question_type": "textarea",
                "required": True,
                "order": 3
            },
            {
                "question": "Why do you want to become a seller on our platform?",
                "question_type": "textarea",
                "required": True,
                "order": 4
            }
        ]
        
        question_objects = []
        for q_data in default_questions:
            question_obj = SellerApplicationQuestion(**q_data)
            await db.seller_questions.insert_one(question_obj.dict())
            question_objects.append(question_obj)
        
        return question_objects
    
    return [SellerApplicationQuestion(**q) for q in questions]

@api_router.post("/admin/seller-application-questions", response_model=SellerApplicationQuestion)
async def create_seller_application_question(
    question_data: SellerApplicationQuestionCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new seller application question"""
    # Get the next order number
    last_question = await db.seller_questions.find({}).sort("order", -1).limit(1).to_list(1)
    next_order = (last_question[0]["order"] + 1) if last_question else 1
    
    question_dict = question_data.dict()
    question_dict["order"] = next_order
    
    question_obj = SellerApplicationQuestion(**question_dict)
    await db.seller_questions.insert_one(question_obj.dict())
    
    return question_obj

@api_router.put("/admin/seller-application-questions/{question_id}", response_model=SellerApplicationQuestion)
async def update_seller_application_question(
    question_id: str,
    question_data: SellerApplicationQuestionUpdate,
    admin_user: User = Depends(get_admin_user)
):
    """Update a seller application question"""
    question = await db.seller_questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    update_data = {k: v for k, v in question_data.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")
    
    await db.seller_questions.update_one({"id": question_id}, {"$set": update_data})
    
    updated_question = await db.seller_questions.find_one({"id": question_id})
    return SellerApplicationQuestion(**updated_question)

@api_router.delete("/admin/seller-application-questions/{question_id}")
async def delete_seller_application_question(
    question_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a seller application question"""
    question = await db.seller_questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")
    
    await db.seller_questions.delete_one({"id": question_id})
    
    # Reorder remaining questions
    remaining_questions = await db.seller_questions.find({}).sort("order", 1).to_list(100)
    for i, q in enumerate(remaining_questions, 1):
        await db.seller_questions.update_one({"id": q["id"]}, {"$set": {"order": i}})
    
    return {"message": "Question deleted successfully"}

@api_router.put("/admin/seller-application-questions/reorder")
async def reorder_seller_application_questions(
    request_data: QuestionReorderRequest,
    admin_user: User = Depends(get_admin_user)
):
    """Reorder seller application questions"""
    # Verify all questions exist first
    for question_id in request_data.question_ids:
        question = await db.seller_questions.find_one({"id": question_id})
        if not question:
            raise HTTPException(status_code=404, detail=f"Question with id {question_id} not found")
    
    # Update the order
    for i, question_id in enumerate(request_data.question_ids, 1):
        result = await db.seller_questions.update_one({"id": question_id}, {"$set": {"order": i}})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail=f"Question with id {question_id} not found")
    
    return {"message": "Questions reordered successfully"}

# Support Ticket System endpoints
@api_router.post("/tickets", response_model=Ticket)
async def create_ticket(
    request: Request,
    ticket_data: TicketCreate,
    current_user: User = Depends(get_current_user)
):
    """Create a new support ticket with enhanced features"""
    # Validate ticket type and priority
    valid_types = ["general", "payment_problem", "account_deletion", "technical_issue", "billing", "other"]
    valid_priorities = ["low", "medium", "high", "critical"]
    valid_severities = ["normal", "high", "critical"]
    
    if ticket_data.ticket_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid ticket type")
    
    if ticket_data.priority not in valid_priorities:
        raise HTTPException(status_code=400, detail="Invalid priority level")
    
    if ticket_data.severity and ticket_data.severity not in valid_severities:
        raise HTTPException(status_code=400, detail="Invalid severity level")
    
    # Create ticket with enhanced features
    ticket_dict = ticket_data.dict()
    ticket_dict["user_id"] = current_user.id
    ticket_dict["username"] = current_user.username
    ticket_dict["email"] = current_user.email
    
    # Initialize activity history
    initial_activity = TicketActivity(
        actor=current_user.username,
        action="created",
        details=f"Ticket created with {ticket_data.priority} priority",
        new_value="open"
    )
    ticket_dict["activity_history"] = [initial_activity.dict()]
    
    ticket_obj = Ticket(**ticket_dict)
    await db.tickets.insert_one(ticket_obj.dict())
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="ticket_created",
        details=f"Created {ticket_data.priority} priority {ticket_data.ticket_type} ticket: {ticket_data.subject}",
        target_id=ticket_obj.id,
        target_type="ticket",
        request=request
    )
    
    # Notify all admins about the new ticket
    try:
        await notify_all_admins(
            title="New Support Ticket Created",
            message=f"User {current_user.username} created a {ticket_data.priority} priority {ticket_data.ticket_type} ticket: {ticket_data.subject}",
            notification_type="info",
            action_url=f"/admin/tickets",
            metadata={
                "ticket_id": ticket_obj.id,
                "user_id": current_user.id,
                "priority": ticket_data.priority,
                "type": ticket_data.ticket_type
            }
        )
    except Exception as e:
        print(f"Failed to notify admins about new ticket: {e}")
    
    return ticket_obj

@api_router.get("/my-tickets", response_model=List[Ticket])
async def get_my_tickets(current_user: User = Depends(get_current_user)):
    """Get current user's tickets"""
    tickets = await db.tickets.find({"user_id": current_user.id}).sort("created_at", -1).to_list(100)
    return [Ticket(**ticket) for ticket in tickets]

@api_router.get("/tickets/{ticket_id}", response_model=Ticket)
async def get_ticket(
    ticket_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get a specific ticket (user can only access their own tickets unless admin)"""
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    # Check if user can access this ticket
    if ticket["user_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You can only access your own tickets")
    
    return Ticket(**ticket)

# Admin ticket management endpoints
@api_router.get("/admin/tickets", response_model=List[Ticket])
async def get_all_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    ticket_type: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = Query(0, ge=0),
    admin_user: User = Depends(get_admin_user)
):
    """Get all tickets with optional filtering"""
    query = {}
    
    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    if ticket_type:
        query["ticket_type"] = ticket_type
    
    tickets = await db.tickets.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [Ticket(**ticket) for ticket in tickets]

@api_router.put("/admin/tickets/{ticket_id}", response_model=Ticket)
async def update_ticket(
    ticket_id: str,
    ticket_update: TicketUpdate,
    request: Request,
    admin_user: User = Depends(get_admin_user)
):
    """Update ticket status and admin response with activity tracking"""
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    
    update_data = {k: v for k, v in ticket_update.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")
    
    # Add timestamp for updates
    update_data["updated_at"] = datetime.utcnow()
    
    # Track activity history
    activity_history = ticket.get("activity_history", [])
    
    # Record status change
    if ticket_update.status and ticket_update.status != ticket["status"]:
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="status_changed",
            details=f"Status changed from '{ticket['status']}' to '{ticket_update.status}'",
            old_value=ticket["status"],
            new_value=ticket_update.status
        ).dict())
        
        # Add resolved timestamp if status is being changed to resolved/closed
        if ticket_update.status in ["resolved", "closed"] and ticket["status"] not in ["resolved", "closed"]:
            update_data["resolved_at"] = datetime.utcnow()
            if not ticket.get("first_response_time"):
                update_data["first_response_time"] = datetime.utcnow()
    
    # Record admin response
    if ticket_update.admin_response:
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="response_added",
            details="Admin response added",
            new_value="Response provided"
        ).dict())
        
        if not ticket.get("first_response_time"):
            update_data["first_response_time"] = datetime.utcnow()
    
    # Record assignment change
    if ticket_update.assigned_to and ticket_update.assigned_to != ticket.get("assigned_to"):
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="assigned",
            details=f"Ticket assigned to {ticket_update.assigned_to_name or ticket_update.assigned_to}",
            old_value=ticket.get("assigned_to_name", ""),
            new_value=ticket_update.assigned_to_name or ticket_update.assigned_to
        ).dict())
    
    update_data["activity_history"] = activity_history
    
    await db.tickets.update_one({"id": ticket_id}, {"$set": update_data})
    
    # Create notification for ticket owner if admin response was provided
    if ticket_update.admin_response:
        await create_notification_helper(
            user_id=ticket["user_id"],
            title="Support Ticket Update 📧",
            message=f"Your support ticket '{ticket['subject']}' has been updated with a response from our team.",
            notification_type="info",
            action_url="/my-tickets",
            metadata={"ticket_id": ticket_id, "subject": ticket["subject"]}
        )
    
    # Create notification for status changes
    if ticket_update.status and ticket_update.status != ticket["status"]:
        status_messages = {
            "resolved": "Your support ticket has been resolved! 🎉",
            "closed": "Your support ticket has been closed.",
            "in_progress": "Your support ticket is now being worked on.",
            "reopened": "Your support ticket has been reopened."
        }
        if ticket_update.status in status_messages:
            await create_notification_helper(
                user_id=ticket["user_id"],
                title="Support Ticket Status Update",
                message=f"{status_messages[ticket_update.status]} Ticket: '{ticket['subject']}'",
                notification_type="success" if ticket_update.status == "resolved" else "info",
                action_url="/my-tickets",
                metadata={"ticket_id": ticket_id, "subject": ticket["subject"], "status": ticket_update.status}
            )
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="ticket_updated",
        details=f"Updated ticket {ticket_id} - Status: {ticket_update.status or 'unchanged'}, Response: {'provided' if ticket_update.admin_response else 'none'}",
        target_id=ticket_id,
        target_type="ticket",
        request=request
    )
    
    # Get updated ticket
    updated_ticket = await db.tickets.find_one({"id": ticket_id})
    return Ticket(**updated_ticket)

@api_router.get("/admin/tickets/stats")
async def get_ticket_stats(admin_user: User = Depends(get_admin_user)):
    """Get ticket statistics for admin dashboard"""
    # Get counts by status
    status_pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    # Get counts by priority
    priority_pipeline = [
        {"$group": {"_id": "$priority", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    # Get counts by type
    type_pipeline = [
        {"$group": {"_id": "$ticket_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    
    status_stats = await db.tickets.aggregate(status_pipeline).to_list(100)
    priority_stats = await db.tickets.aggregate(priority_pipeline).to_list(100)
    type_stats = await db.tickets.aggregate(type_pipeline).to_list(100)
    
    total_tickets = await db.tickets.count_documents({})
    
    return {
        "total_tickets": total_tickets,
        "status_stats": status_stats,
        "priority_stats": priority_stats,
        "type_stats": type_stats
    }

# Knowledge Base endpoints
@api_router.get("/knowledge-base", response_model=List[KnowledgeBaseArticle])
async def get_knowledge_base_articles(
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0
):
    """Get knowledge base articles with optional filtering"""
    query = {"status": "published"}
    
    if category:
        query["category"] = category
    
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"content": {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tags": {"$in": [search]}}
        ]
    
    articles = await db.knowledge_base.find(query).sort("helpful_votes", -1).skip(skip).limit(limit).to_list(limit)
    return [KnowledgeBaseArticle(**article) for article in articles]

@api_router.get("/knowledge-base/search-suggestions")
async def get_knowledge_base_suggestions(
    query: str,
    ticket_type: Optional[str] = None,
    limit: int = 5
):
    """Get knowledge base article suggestions based on ticket content"""
    search_query = {
        "status": "published",
        "$or": [
            {"title": {"$regex": query, "$options": "i"}},
            {"content": {"$regex": query, "$options": "i"}},
            {"summary": {"$regex": query, "$options": "i"}},
            {"tags": {"$in": [query]}}
        ]
    }
    
    if ticket_type:
        search_query["$or"].append({"category": ticket_type})
    
    articles = await db.knowledge_base.find(search_query).sort("helpful_votes", -1).limit(limit).to_list(limit)
    
    return [
        {
            "id": article["id"],
            "title": article["title"],
            "summary": article["summary"],
            "category": article.get("category", ""),
            "helpful_votes": article.get("helpful_votes", 0)
        }
        for article in articles
    ]

@api_router.get("/knowledge-base/{article_id}", response_model=KnowledgeBaseArticle)
async def get_knowledge_base_article(article_id: str):
    """Get a specific knowledge base article and increment view count"""
    article = await db.knowledge_base.find_one({"id": article_id, "status": "published"})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Increment view count
    await db.knowledge_base.update_one(
        {"id": article_id},
        {"$inc": {"views": 1}}
    )
    
    article["views"] = article.get("views", 0) + 1
    return KnowledgeBaseArticle(**article)

@api_router.post("/knowledge-base/{article_id}/vote")
async def vote_on_article(
    article_id: str,
    helpful: bool,
    current_user: User = Depends(get_current_user)
):
    """Vote on whether an article was helpful"""
    article = await db.knowledge_base.find_one({"id": article_id})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Check if user already voted
    existing_vote = await db.article_votes.find_one({"article_id": article_id, "user_id": current_user.id})
    if existing_vote:
        raise HTTPException(status_code=400, detail="You have already voted on this article")
    
    # Record vote
    vote_data = {
        "id": str(uuid.uuid4()),
        "article_id": article_id,
        "user_id": current_user.id,
        "helpful": helpful,
        "created_at": datetime.utcnow()
    }
    await db.article_votes.insert_one(vote_data)
    
    # Update article vote counts
    if helpful:
        await db.knowledge_base.update_one({"id": article_id}, {"$inc": {"helpful_votes": 1}})
    else:
        await db.knowledge_base.update_one({"id": article_id}, {"$inc": {"not_helpful_votes": 1}})
    
    return {"message": "Vote recorded successfully"}

# Ticket Template endpoints
@api_router.get("/ticket-templates", response_model=List[TicketTemplate])
async def get_ticket_templates(ticket_type: Optional[str] = None):
    """Get ticket templates"""
    query = {}
    if ticket_type:
        query["ticket_type"] = ticket_type
    
    templates = await db.ticket_templates.find(query).to_list(100)
    return [TicketTemplate(**template) for template in templates]

@api_router.get("/ticket-categories")
async def get_ticket_categories():
    """Get available ticket categories for better organization"""
    categories = [
        {"value": "account", "label": "Account Issues", "icon": "👤"},
        {"value": "payment", "label": "Payment & Billing", "icon": "💳"},
        {"value": "technical", "label": "Technical Support", "icon": "🔧"},
        {"value": "product", "label": "Product Issues", "icon": "📦"},
        {"value": "feedback", "label": "Feedback & Suggestions", "icon": "💭"},
        {"value": "security", "label": "Security Concerns", "icon": "🔒"},
        {"value": "legal", "label": "Legal & Compliance", "icon": "⚖️"},
        {"value": "other", "label": "Other", "icon": "❓"}
    ]
    
    return categories

# Admin Knowledge Base Management
@api_router.post("/admin/knowledge-base", response_model=KnowledgeBaseArticle)
async def create_knowledge_base_article(
    article_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new knowledge base article (admin only)"""
    article_dict = {
        "id": str(uuid.uuid4()),
        "author": admin_user.username,
        "helpful_votes": 0,
        "not_helpful_votes": 0,
        "views": 0,
        "created_at": datetime.utcnow(),
        **article_data
    }
    
    article_obj = KnowledgeBaseArticle(**article_dict)
    await db.knowledge_base.insert_one(article_obj.dict())
    
    return article_obj

@api_router.put("/admin/knowledge-base/{article_id}", response_model=KnowledgeBaseArticle)
async def update_knowledge_base_article(
    article_id: str,
    article_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Update an existing knowledge base article (admin only)"""
    # Check if article exists
    existing_article = await db.knowledge_base.find_one({"id": article_id})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Update the article data
    update_data = {
        **article_data,
        "updated_at": datetime.utcnow()
    }
    
    await db.knowledge_base.update_one(
        {"id": article_id},
        {"$set": update_data}
    )
    
    # Get updated article
    updated_article = await db.knowledge_base.find_one({"id": article_id})
    return KnowledgeBaseArticle(**updated_article)

@api_router.delete("/admin/knowledge-base/{article_id}")
async def delete_knowledge_base_article(
    article_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a knowledge base article (admin only)"""
    # Check if article exists
    existing_article = await db.knowledge_base.find_one({"id": article_id})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Article not found")
    
    # Delete the article
    result = await db.knowledge_base.delete_one({"id": article_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Article not found")
    
    return {"message": "Article deleted successfully", "article_id": article_id}

@api_router.get("/admin/knowledge-base/drafts", response_model=List[KnowledgeBaseArticle])
async def get_draft_articles(
    admin_user: User = Depends(get_admin_user)
):
    """Get all draft knowledge base articles (admin only)"""
    articles = await db.knowledge_base.find({"status": "draft"}).sort("created_at", -1).to_list(length=100)
    return [KnowledgeBaseArticle(**article) for article in articles]

@api_router.put("/admin/knowledge-base/{article_id}/publish")
async def publish_article(
    article_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Publish a draft article (admin only)"""
    # Check if article exists and is a draft
    existing_article = await db.knowledge_base.find_one({"id": article_id, "status": "draft"})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Draft article not found")
    
    # Update article status to published
    result = await db.knowledge_base.update_one(
        {"id": article_id},
        {"$set": {"status": "published", "updated_at": datetime.utcnow()}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Article not found")
    
    return {"message": "Article published successfully", "article_id": article_id}

@api_router.post("/admin/ticket-templates", response_model=TicketTemplate)
async def create_ticket_template(
    template_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new ticket template (admin only)"""
    template_dict = {
        "id": str(uuid.uuid4()),
        **template_data
    }
    
    template_obj = TicketTemplate(**template_dict)
    await db.ticket_templates.insert_one(template_obj.dict())
    
    return template_obj
    
@api_router.post("/seller-application", response_model=SellerApplication)
async def submit_seller_application(
    request: Request,
    application_data: SellerApplicationCreate,
    current_user: User = Depends(get_current_user)
):
    if current_user.user_type != "buyer":
        raise HTTPException(status_code=400, detail="Only buyers can apply to become sellers")
    
    # Check if user already has an application
    existing_application = await db.seller_applications.find_one({"user_id": current_user.id})
    if existing_application:
        raise HTTPException(status_code=400, detail="You have already submitted a seller application")
    
    # Create application
    application_dict = application_data.dict()
    application_dict["user_id"] = current_user.id
    application_dict["username"] = current_user.username
    application_dict["email"] = current_user.email
    
    application_obj = SellerApplication(**application_dict)
    await db.seller_applications.insert_one(application_obj.dict())
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="seller_application",
        details=f"Submitted seller application with {len(application_data.answers)} question responses",
        target_id=application_obj.id,
        target_type="application",
        request=request
    )
    
    # Notify all admins about the new application
    try:
        await notify_all_admins(
            title="New Seller Application Submitted",
            message=f"User {current_user.username} ({current_user.email}) has submitted a seller application and is awaiting review.",
            notification_type="info",
            action_url="/admin/applications",
            metadata={
                "application_id": application_obj.id,
                "user_id": current_user.id,
                "username": current_user.username,
                "email": current_user.email
            }
        )
    except Exception as e:
        print(f"Failed to notify admins about new application: {e}")
    
    return application_obj

@api_router.get("/my-seller-application", response_model=SellerApplication)
async def get_my_seller_application(current_user: User = Depends(get_current_user)):
    application = await db.seller_applications.find_one({"user_id": current_user.id})
    if not application:
        raise HTTPException(status_code=404, detail="No seller application found")
    
    return SellerApplication(**application)

# Admin seller application management
@api_router.get("/admin/seller-applications", response_model=List[SellerApplication])
async def get_seller_applications(
    status: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    query = {}
    if status:
        query["status"] = status
    
    applications = await db.seller_applications.find(query).to_list(100)
    return [SellerApplication(**app) for app in applications]

@api_router.put("/admin/seller-applications/{application_id}")
async def review_seller_application(
    application_id: str,
    status: str,  # approved, rejected
    admin_notes: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    application = await db.seller_applications.find_one({"id": application_id})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")
    
    # Update application status
    update_data = {
        "status": status,
        "reviewed_at": datetime.utcnow(),
        "reviewed_by": admin_user.id
    }
    if admin_notes:
        update_data["admin_notes"] = admin_notes
    
    await db.seller_applications.update_one(
        {"id": application_id},
        {"$set": update_data}
    )
    
    # If approved, update user to seller
    if status == "approved":
        await db.users.update_one(
            {"id": application["user_id"]},
            {"$set": {"user_type": "seller"}}
        )
        
        # Create notification for user
        await create_notification_helper(
            user_id=application["user_id"],
            title="Seller Application Approved! 🎉",
            message="Congratulations! Your seller application has been approved. You can now start selling products on our marketplace.",
            notification_type="success",
            action_url="/sell",
            metadata={"application_id": application_id}
        )
    elif status == "rejected":
        # Create notification for user
        await create_notification_helper(
            user_id=application["user_id"],
            title="Seller Application Update",
            message=f"Your seller application has been reviewed. {admin_notes or 'Please contact support for more information.'}",
            notification_type="warning",
            action_url="/apply-seller",
            metadata={"application_id": application_id, "admin_notes": admin_notes}
        )
    
    return {"message": "Application reviewed successfully"}

@api_router.put("/admin/users/{user_id}/manage")
async def admin_manage_user_profile(
    user_id: str,
    action: str,  # ban, unban, promote, demote, make_seller, remove_seller
    reason: Optional[str] = None,  # For ban action
    ban_type: Optional[str] = None,  # permanent, temporary
    ban_duration_days: Optional[int] = None,  # For temporary bans
    admin_user: User = Depends(get_admin_user)
):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    update_data = {}
    
    if action == "ban":
        if not ban_type or ban_type not in ["permanent", "temporary"]:
            raise HTTPException(status_code=400, detail="Ban type must be 'permanent' or 'temporary'")
        
        update_data["status"] = "banned"
        update_data["ban_reason"] = reason or "No reason provided"
        update_data["ban_time"] = datetime.utcnow()
        update_data["ban_type"] = ban_type
        
        if ban_type == "temporary":
            if not ban_duration_days or ban_duration_days <= 0:
                raise HTTPException(status_code=400, detail="Temporary ban requires valid duration in days")
            update_data["ban_expires_at"] = datetime.utcnow() + timedelta(days=ban_duration_days)
        else:
            update_data["ban_expires_at"] = None
            
    elif action == "unban":
        update_data["status"] = "active"
        update_data["ban_reason"] = ""
        update_data["ban_time"] = None
        update_data["ban_type"] = None
        update_data["ban_expires_at"] = None
    elif action == "promote":
        update_data["role"] = "admin"
    elif action == "demote":
        update_data["role"] = "user"
    elif action == "make_seller":
        update_data["user_type"] = "seller"
    elif action == "remove_seller":
        update_data["user_type"] = "buyer"
    else:
        raise HTTPException(status_code=400, detail="Invalid action")
    
    await db.users.update_one({"id": user_id}, {"$set": update_data})
    
    return {"message": f"User {action} action completed successfully"}

@api_router.put("/admin/users/{user_id}/notes")
async def update_admin_notes(
    user_id: str,
    notes: str,
    admin_user: User = Depends(get_admin_user)
):
    """Update admin notes for a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"admin_notes": notes}}
    )
    
    # Log the admin note update
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="admin_notes_updated",
        details=f"Updated admin notes for user {user['username']}",
        target_id=user_id,
        target_type="user"
    )
    
    return {"message": "Admin notes updated successfully"}

# Role Management Endpoints

@api_router.post("/admin/custom-roles")
async def create_custom_role_template(
    role_data: CustomRoleCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new custom role template"""
    # Check if role name already exists
    existing_role = await db.custom_role_templates.find_one({"name": role_data.name})
    if existing_role:
        raise HTTPException(status_code=400, detail="Role name already exists")
    
    new_role_template = CustomRoleTemplate(
        **role_data.dict(),
        created_by=admin_user.id
    )
    
    await db.custom_role_templates.insert_one(new_role_template.dict())
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="custom_role_created",
        details=f"Created custom role template: {role_data.name}",
        target_id=new_role_template.id,
        target_type="custom_role"
    )
    
    return {"message": "Custom role template created successfully", "role": new_role_template}

@api_router.get("/admin/custom-roles")
async def get_custom_role_templates(admin_user: User = Depends(get_admin_user)):
    """Get all custom role templates"""
    roles = await db.custom_role_templates.find({}).to_list(100)
    return [CustomRoleTemplate(**role) for role in roles]

@api_router.delete("/admin/custom-roles/{role_id}")
async def delete_custom_role_template(
    role_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a custom role template"""
    role = await db.custom_role_templates.find_one({"id": role_id})
    if not role:
        raise HTTPException(status_code=404, detail="Custom role not found")
    
    # Remove this custom role from all users who have it
    await db.users.update_many(
        {"custom_role.name": role["name"]},
        {"$unset": {"custom_role": ""}}
    )
    
    # Delete the role template
    await db.custom_role_templates.delete_one({"id": role_id})
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="custom_role_deleted",
        details=f"Deleted custom role template: {role['name']}",
        target_id=role_id,
        target_type="custom_role"
    )
    
    return {"message": "Custom role template deleted successfully"}

@api_router.put("/admin/custom-roles/{role_id}")
async def update_custom_role_template(
    role_id: str,
    role_data: CustomRoleCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Update a custom role template and propagate changes to all users with this role"""
    # Find the existing role template
    existing_role = await db.custom_role_templates.find_one({"id": role_id})
    if not existing_role:
        raise HTTPException(status_code=404, detail="Custom role template not found")
    
    # Check if the new name already exists (only if name is being changed)
    if role_data.name != existing_role["name"]:
        name_exists = await db.custom_role_templates.find_one({
            "name": role_data.name,
            "id": {"$ne": role_id}
        })
        if name_exists:
            raise HTTPException(status_code=400, detail="Role name already exists")
    
    # Update the role template
    updated_data = {
        "name": role_data.name,
        "icon": role_data.icon,
        "color": role_data.color,
        "updated_at": datetime.utcnow()
    }
    
    await db.custom_role_templates.update_one(
        {"id": role_id},
        {"$set": updated_data}
    )
    
    # Update all users who have this role assigned
    # First find users with the old role name
    users_with_role = await db.users.find({
        "custom_role.name": existing_role["name"]
    }).to_list(1000)
    
    if users_with_role:
        # Update their custom_role with new data
        new_custom_role = {
            "name": role_data.name,
            "icon": role_data.icon,
            "color": role_data.color
        }
        
        await db.users.update_many(
            {"custom_role.name": existing_role["name"]},
            {"$set": {"custom_role": new_custom_role}}
        )
        
        # Also update public profiles
        await db.public_profiles.update_many(
            {"custom_role.name": existing_role["name"]},
            {"$set": {"custom_role": new_custom_role}}
        )
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="custom_role_updated",
        details=f"Updated custom role template: {existing_role['name']} -> {role_data.name} (affects {len(users_with_role)} users)",
        target_id=role_id,
        target_type="custom_role"
    )
    
    # Get the updated role template
    updated_role = await db.custom_role_templates.find_one({"id": role_id})
    
    return {
        "message": "Custom role template updated successfully",
        "role": CustomRoleTemplate(**updated_role),
        "affected_users": len(users_with_role)
    }

@api_router.put("/admin/users/{user_id}/user-type")
async def update_user_type(
    user_id: str,
    user_type_data: UserTypeUpdate,
    admin_user: User = Depends(get_admin_user)
):
    """Update user type (buyer/seller)"""
    if user_type_data.user_type not in ["buyer", "seller"]:
        raise HTTPException(status_code=400, detail="Invalid user type. Must be 'buyer' or 'seller'")
    
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_user_type = user.get("user_type", "buyer")
    
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"user_type": user_type_data.user_type}}
    )
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="user_type_updated",
        details=f"Changed user type from {old_user_type} to {user_type_data.user_type} for user {user['username']}",
        target_id=user_id,
        target_type="user"
    )
    
    return {"message": f"User type updated to {user_type_data.user_type} successfully"}

@api_router.put("/admin/users/{user_id}/custom-role")
async def assign_custom_role(
    user_id: str,
    role_data: AssignCustomRole,
    admin_user: User = Depends(get_admin_user)
):
    """Assign a custom role to a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    custom_role = CustomRole(
        name=role_data.role_name,
        icon=role_data.icon,
        color=role_data.color
    )
    
    await db.users.update_one(
        {"id": user_id},
        {"$set": {"custom_role": custom_role.dict()}}
    )
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="custom_role_assigned",
        details=f"Assigned custom role '{role_data.role_name}' to user {user['username']}",
        target_id=user_id,
        target_type="user"
    )
    
    return {"message": f"Custom role '{role_data.role_name}' assigned successfully"}

@api_router.delete("/admin/users/{user_id}/custom-role")
async def remove_custom_role(
    user_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Remove custom role from a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    old_role = user.get("custom_role", {}).get("name", "None")
    
    await db.users.update_one(
        {"id": user_id},
        {"$unset": {"custom_role": ""}}
    )
    
    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="custom_role_removed",
        details=f"Removed custom role '{old_role}' from user {user['username']}",
        target_id=user_id,
        target_type="user"
    )
    
    return {"message": "Custom role removed successfully"}

@api_router.get("/custom-role-icons")
async def get_predefined_icons():
    """Get predefined icons for custom roles"""
    icons = [
        "👑", "💎", "⭐", "🎯", "🚀", "💡", "🔥", "⚡", "🎨", "🏆",
        "🎪", "🎭", "🎸", "🎤", "🎬", "📸", "🎮", "🕹️", "🎲", "🃏",
        "🏅", "🥇", "🥈", "🥉", "🏵️", "🎖️", "🏆", "🏴", "🚩", "🎌"
    ]
    return {"icons": icons}

@api_router.get("/admin/users/{user_id}/notes")
async def get_admin_notes(
    user_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Get admin notes for a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"admin_notes": user.get("admin_notes", "")}

@api_router.get("/admin/expired-bans/check")
async def check_expired_bans(admin_user: User = Depends(get_admin_user)):
    """Manually trigger check for expired temporary bans"""
    unbanned_count = await check_and_unban_expired_users()
    return {"message": f"Checked expired bans. Unbanned {unbanned_count} users."}

# Product endpoints
@api_router.post("/products", response_model=Product)
async def create_product(
    request: Request,
    title: str = Form(...),
    description: str = Form(...),
    price: float = Form(...),
    category: str = Form(...),
    file: UploadFile = File(...),
    image: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user)
):
    if current_user.user_type != "seller":
        raise HTTPException(status_code=403, detail="Only sellers can create products")
    
    # Save uploaded file
    file_id = str(uuid.uuid4())
    file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
    stored_filename = f"{file_id}.{file_extension}"
    file_path = UPLOAD_DIR / stored_filename
    
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    # Handle product image
    image_data = ""
    if image and image.content_type.startswith('image/'):
        # Convert image to base64
        image_content = await image.read()
        image_base64 = base64.b64encode(image_content).decode('utf-8')
        image_data = f"data:{image.content_type};base64,{image_base64}"
    
    # Create product
    product_dict = {
        "title": title,
        "description": description,
        "price": price,
        "category": category,
        "seller_id": current_user.id,
        "seller_name": current_user.username,
        "file_name": stored_filename,
        "original_filename": file.filename if file.filename else "unknown",
        "file_size": file_path.stat().st_size,
        "image": image_data,
        "status": "pending"  # All new products require admin approval
    }
    
    product_obj = Product(**product_dict)
    await db.products.insert_one(product_obj.dict())
    
    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="product_created",
        details=f"Created product '{title}' in category '{category}' for ${price}",
        target_id=product_obj.id,
        target_type="product",
        request=request
    )
    
    return product_obj

@api_router.get("/products", response_model=List[Product])
async def get_products(category: Optional[str] = None, search: Optional[str] = None):
    query = {"status": "approved"}  # Only show approved products
    if category:
        query["category"] = category
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}}
        ]
    
    products = await db.products.find(query).to_list(100)
    return [Product(**product) for product in products]

@api_router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id, "status": "approved"})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return Product(**product)

@api_router.get("/my-products", response_model=List[Product])
async def get_my_products(current_user: User = Depends(get_current_user)):
    if current_user.user_type != "seller":
        raise HTTPException(status_code=403, detail="Only sellers can view their products")
    
    products = await db.products.find({"seller_id": current_user.id}).to_list(100)
    return [Product(**product) for product in products]

# Rating endpoints
@api_router.post("/ratings", response_model=Rating)
async def create_rating(
    rating_data: RatingCreate,
    current_user: User = Depends(get_current_user)
):
    # Check if product exists and user purchased it
    product = await db.products.find_one({"id": rating_data.product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Check if user purchased this product
    purchase = await db.purchases.find_one({
        "buyer_id": current_user.id,
        "product_id": rating_data.product_id
    })
    if not purchase:
        raise HTTPException(status_code=403, detail="You can only rate products you have purchased")
    
    # Check if user already rated this product
    existing_rating = await db.ratings.find_one({
        "product_id": rating_data.product_id,
        "user_id": current_user.id
    })
    if existing_rating:
        raise HTTPException(status_code=400, detail="You have already rated this product")
    
    # Create rating
    rating_dict = rating_data.dict()
    rating_dict["user_id"] = current_user.id
    rating_dict["username"] = current_user.username
    
    rating_obj = Rating(**rating_dict)
    await db.ratings.insert_one(rating_obj.dict())
    
    # Update product rating average
    await update_product_rating(rating_data.product_id)
    
    return rating_obj

@api_router.get("/ratings/{product_id}", response_model=List[RatingResponse])
async def get_product_ratings(product_id: str, current_user: Optional[User] = Depends(get_current_user_optional)):
    ratings = await db.ratings.find({"product_id": product_id}).to_list(100)
    
    result = []
    for rating_data in ratings:
        rating = Rating(**rating_data)
        can_edit = current_user and current_user.id == rating.user_id
        result.append(RatingResponse(rating=rating, can_edit=can_edit))
    
    return result

@api_router.put("/ratings/{rating_id}", response_model=Rating)
async def update_rating(
    rating_id: str,
    rating_data: RatingCreate,
    current_user: User = Depends(get_current_user)
):
    # Find existing rating
    existing_rating = await db.ratings.find_one({"id": rating_id})
    if not existing_rating:
        raise HTTPException(status_code=404, detail="Rating not found")
    
    # Check ownership
    if existing_rating["user_id"] != current_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own ratings")
    
    # Update rating
    update_data = {
        "rating": rating_data.rating,
        "review": rating_data.review,
        "updated_at": datetime.utcnow()
    }
    
    await db.ratings.update_one({"id": rating_id}, {"$set": update_data})
    
    # Update product rating average
    await update_product_rating(existing_rating["product_id"])
    
    # Return updated rating
    updated_rating = await db.ratings.find_one({"id": rating_id})
    return Rating(**updated_rating)

# Payment endpoints
@api_router.post("/payments/checkout")
async def create_checkout_session(
    product_id: str,
    request: Request,
    current_user: User = Depends(get_current_user)
):
    # Get product
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Check if user already owns this product
    existing_purchase = await db.purchases.find_one({
        "buyer_id": current_user.id,
        "product_id": product_id
    })
    if existing_purchase:
        raise HTTPException(status_code=400, detail="Product already purchased")
    
    # Initialize Stripe
    host_url = str(request.base_url).rstrip('/')
    webhook_url = f"{host_url}/api/webhook/stripe"
    stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url=webhook_url)
    
    # Create checkout session
    success_url = f"{host_url}/purchase-success?session_id={{CHECKOUT_SESSION_ID}}&product_id={product_id}"
    cancel_url = f"{host_url}/product/{product_id}"
    
    checkout_request = CheckoutSessionRequest(
        amount=product["price"],
        currency="usd",
        success_url=success_url,
        cancel_url=cancel_url,
        metadata={
            "product_id": product_id,
            "buyer_id": current_user.id,
            "seller_id": product["seller_id"]
        }
    )
    
    session = await stripe_checkout.create_checkout_session(checkout_request)
    
    # Create payment transaction record
    payment_transaction = PaymentTransaction(
        session_id=session.session_id,
        product_id=product_id,
        buyer_id=current_user.id,
        seller_id=product["seller_id"],
        amount=product["price"],
        currency="usd",
        payment_status="pending",
        stripe_status="initiated",
        metadata=checkout_request.metadata
    )
    
    await db.payment_transactions.insert_one(payment_transaction.dict())
    
    return {"checkout_url": session.url, "session_id": session.session_id}

@api_router.get("/payments/status/{session_id}")
async def get_payment_status(session_id: str, current_user: User = Depends(get_current_user)):
    # Get payment transaction
    transaction = await db.payment_transactions.find_one({"session_id": session_id})
    if not transaction:
        raise HTTPException(status_code=404, detail="Payment session not found")
    
    # Initialize Stripe
    stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url="")
    
    # Get checkout status from Stripe
    checkout_status = await stripe_checkout.get_checkout_status(session_id)
    
    # Update transaction status
    update_data = {
        "stripe_status": checkout_status.status,
        "payment_status": checkout_status.payment_status,
        "updated_at": datetime.utcnow()
    }
    
    await db.payment_transactions.update_one(
        {"session_id": session_id},
        {"$set": update_data}
    )
    
    # If payment successful and not already processed, create purchase record
    if checkout_status.payment_status == "paid":
        existing_purchase = await db.purchases.find_one({
            "buyer_id": transaction["buyer_id"],
            "product_id": transaction["product_id"]
        })
        
        if not existing_purchase:
            # Create download token
            download_token = hashlib.sha256(f"{session_id}{transaction['product_id']}{transaction['buyer_id']}".encode()).hexdigest()
            
            purchase = Purchase(
                buyer_id=transaction["buyer_id"],
                product_id=transaction["product_id"],
                seller_id=transaction["seller_id"],
                transaction_id=transaction["id"],
                download_token=download_token
            )
            
            await db.purchases.insert_one(purchase.dict())
            
            # Get product and user details for notification
            product = await db.products.find_one({"id": transaction["product_id"]})
            buyer = await db.users.find_one({"id": transaction["buyer_id"]})
            seller = await db.users.find_one({"id": transaction["seller_id"]})
            
            # Create notification for buyer
            if buyer and product:
                await create_notification_helper(
                    user_id=buyer["id"],
                    title="Purchase Successful! 🎉",
                    message=f"You have successfully purchased '{product['title']}'. You can now download it from your purchases page.",
                    notification_type="success",
                    action_url="/my-purchases",
                    metadata={"product_id": product["id"], "product_title": product["title"]}
                )
            
            # Create notification for seller
            if seller and product:
                await create_notification_helper(
                    user_id=seller["id"],
                    title="New Sale! 💰",
                    message=f"Congratulations! Your product '{product['title']}' has been purchased by {buyer['username']}.",
                    notification_type="success",
                    action_url="/my-products",
                    metadata={"product_id": product["id"], "product_title": product["title"], "buyer_username": buyer["username"]}
                )
            
            # Update product download count
            await db.products.update_one(
                {"id": transaction["product_id"]},
                {"$inc": {"downloads": 1}}
            )
    
    return {
        "status": checkout_status.status,
        "payment_status": checkout_status.payment_status,
        "amount_total": checkout_status.amount_total,
        "currency": checkout_status.currency
    }

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    try:
        webhook_request_body = await request.body()
        stripe_signature = request.headers.get("Stripe-Signature")
        
        if not stripe_signature:
            return {"status": "ok", "message": "No signature provided"}
        
        stripe_checkout = StripeCheckout(api_key=stripe_api_key, webhook_url="")
        webhook_response = await stripe_checkout.handle_webhook(webhook_request_body, stripe_signature)
        
        # Update payment transaction
        if webhook_response.session_id:
            update_data = {
                "stripe_status": webhook_response.event_type,
                "payment_status": webhook_response.payment_status,
                "updated_at": datetime.utcnow()
            }
            
            await db.payment_transactions.update_one(
                {"session_id": webhook_response.session_id},
                {"$set": update_data}
            )
        
        return {"status": "ok"}
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return {"status": "ok", "message": "Webhook processed with errors"}

# Admin debug purchase endpoint
@api_router.post("/admin/debug-purchase")
async def debug_purchase(
    request: DebugPurchaseRequest,
    admin_user: User = Depends(get_admin_user)
):
    """
    Debug endpoint for admins to simulate product purchases without payment processing.
    Creates a purchase record directly in the database for testing purposes.
    """
    try:
        # Get product
        product = await db.products.find_one({"id": request.product_id})
        if not product:
            raise HTTPException(
                status_code=404, 
                detail=f"Product with ID '{request.product_id}' not found"
            )
        
        # Validate product is approved and active
        if product.get("status") != "approved":
            raise HTTPException(
                status_code=400, 
                detail=f"Cannot create debug purchase for product with status '{product.get('status')}'. Product must be approved."
            )
        
        # Determine buyer - use provided buyer_id or admin user
        if request.buyer_id:
            # Validate buyer exists
            buyer = await db.users.find_one({"id": request.buyer_id})
            if not buyer:
                raise HTTPException(
                    status_code=404, 
                    detail=f"Buyer user with ID '{request.buyer_id}' not found"
                )
            
            # Validate buyer is not the seller (prevent self-purchase)
            if request.buyer_id == product["seller_id"]:
                raise HTTPException(
                    status_code=400, 
                    detail="Cannot create debug purchase: buyer cannot be the same as the product seller"
                )
            
            actual_buyer_id = request.buyer_id
            buyer_username = buyer["username"]
        else:
            # Use admin as buyer
            buyer = admin_user
            actual_buyer_id = admin_user.id
            buyer_username = admin_user.username
        
        # Check if user already owns this product (duplicate purchase validation)
        existing_purchase = await db.purchases.find_one({
            "buyer_id": actual_buyer_id,
            "product_id": request.product_id
        })
        if existing_purchase:
            raise HTTPException(
                status_code=400, 
                detail=f"Product '{product['title']}' has already been purchased by user '{buyer_username}'. Duplicate purchases are not allowed."
            )
        
        # Get seller details for validation and notifications
        seller = await db.users.find_one({"id": product["seller_id"]})
        if not seller:
            raise HTTPException(
                status_code=404, 
                detail=f"Product seller with ID '{product['seller_id']}' not found"
            )
        
        # Generate debug session ID and download token
        debug_session_id = f"debug_{uuid.uuid4().hex[:16]}"
        download_token = hashlib.sha256(f"{debug_session_id}{request.product_id}{actual_buyer_id}".encode()).hexdigest()
        
        # Create debug payment transaction record
        payment_transaction = PaymentTransaction(
            session_id=debug_session_id,
            product_id=request.product_id,
            buyer_id=actual_buyer_id,
            seller_id=product["seller_id"],
            amount=product["price"],
            currency="usd",
            payment_status="paid",  # Mark as paid since this is debug mode
            stripe_status="debug_completed",
            metadata={
                "debug_mode": True,
                "admin_user": admin_user.id,
                "admin_username": admin_user.username,
                "product_id": request.product_id,
                "buyer_id": actual_buyer_id,
                "seller_id": product["seller_id"],
                "created_by": "admin_debug_endpoint"
            }
        )
        
        await db.payment_transactions.insert_one(payment_transaction.dict())
        
        # Create purchase record
        purchase = Purchase(
            buyer_id=actual_buyer_id,
            product_id=request.product_id,
            seller_id=product["seller_id"],
            transaction_id=payment_transaction.id,
            download_token=download_token
        )
        
        await db.purchases.insert_one(purchase.dict())
        
        # Create notification for buyer (if not admin)
        if actual_buyer_id != admin_user.id:
            await create_notification_helper(
                user_id=actual_buyer_id,
                title="Debug Purchase Successful! 🧪",
                message=f"Admin has created a debug purchase for '{product['title']}'. You can now access it from your purchases page.",
                notification_type="info",
                action_url="/my-purchases",
                metadata={
                    "debug_mode": True,
                    "product_id": product["id"], 
                    "product_title": product["title"],
                    "admin_user": admin_user.username
                }
            )
        
        # Create notification for seller (if not admin)
        if seller and seller["id"] != admin_user.id:
            await create_notification_helper(
                user_id=seller["id"],
                title="Debug Sale Created! 🧪",
                message=f"Admin has created a debug purchase of your product '{product['title']}' for testing purposes.",
                notification_type="info",
                action_url="/my-products",
                metadata={
                    "debug_mode": True,
                    "product_id": product["id"], 
                    "product_title": product["title"], 
                    "buyer_username": buyer_username,
                    "admin_user": admin_user.username
                }
            )
        
        # Update product download count
        await db.products.update_one(
            {"id": request.product_id},
            {"$inc": {"downloads": 1}}
        )
        
        # Log activity
        await log_activity(
            user_id=admin_user.id,
            username=admin_user.username,
            action="debug_purchase_created",
            details=f"Admin {admin_user.username} created debug purchase of product '{product['title']}' for user {buyer_username}",
            target_id=purchase.id,
            target_type="purchase"
        )
        
        return {
            "success": True,
            "message": "Debug purchase created successfully",
            "purchase_id": purchase.id,
            "session_id": debug_session_id,
            "download_token": download_token,
            "buyer": {
                "id": actual_buyer_id,
                "username": buyer_username
            },
            "product": {
                "id": product["id"],
                "title": product["title"],
                "price": product["price"]
            },
            "seller": {
                "id": seller["id"],
                "username": seller["username"]
            },
            "debug_info": {
                "created_by": admin_user.username,
                "created_at": datetime.utcnow().isoformat()
            }
        }
        
    except HTTPException:
        # Re-raise HTTP exceptions as they are already properly formatted
        raise
    except Exception as e:
        # Log unexpected errors and return 500
        logger.error(f"Unexpected error in debug purchase endpoint: {str(e)}")
        raise HTTPException(
            status_code=500, 
            detail=f"Internal server error occurred while creating debug purchase: {str(e)}"
        )

# Download endpoint
@api_router.get("/download/{download_token}")
async def download_file(download_token: str, current_user: User = Depends(get_current_user)):
    # Find purchase by download token
    purchase = await db.purchases.find_one({
        "download_token": download_token,
        "buyer_id": current_user.id
    })
    
    if not purchase:
        raise HTTPException(status_code=404, detail="Download not found or unauthorized")
    
    # Get product info
    product = await db.products.find_one({"id": purchase["product_id"]})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Get file path
    file_path = UPLOAD_DIR / product["file_name"]
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    # Verify file integrity
    try:
        file_size = file_path.stat().st_size
        if file_size == 0:
            raise HTTPException(status_code=500, detail="File is empty or corrupted")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File access error: {str(e)}")
    
    # Create safe filename - try using sanitized product title, fallback to original filename
    original_filename = product.get("original_filename", "")
    file_extension = product["file_name"].split('.')[-1].lower()
    
    # Try to create filename from product title
    if product.get("title"):
        base_filename = f"{product['title']}.{file_extension}"
        safe_filename = sanitize_filename(base_filename)
    else:
        # Fallback to original filename or generic name
        safe_filename = sanitize_filename(original_filename) if original_filename else f"download.{file_extension}"
    
    # Ensure the safe filename is not empty and has proper extension
    if not safe_filename or safe_filename == "download":
        safe_filename = f"download.{file_extension}"
    
    # Determine proper media type based on file extension
    media_type = get_media_type_for_file(file_extension)
    
    # Create FileResponse with proper headers
    response = FileResponse(
        path=file_path,
        filename=safe_filename,
        media_type=media_type
    )
    
    # Add additional headers for better download handling
    from urllib.parse import quote
    encoded_filename = quote(safe_filename.encode('utf-8'))
    response.headers["Content-Disposition"] = f'attachment; filename="{safe_filename}"; filename*=UTF-8\'\'{encoded_filename}'
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Content-Length"] = str(file_size)
    
    return response

@api_router.get("/my-purchases", response_model=List[Dict])
async def get_my_purchases(current_user: User = Depends(get_current_user)):
    purchases = await db.purchases.find({"buyer_id": current_user.id}).to_list(100)
    
    result = []
    for purchase in purchases:
        product = await db.products.find_one({"id": purchase["product_id"]})
        if product:
            result.append({
                "purchase": Purchase(**purchase),
                "product": Product(**product)
            })
    
    return result

# Admin endpoints
@api_router.get("/admin/dashboard")
async def get_admin_dashboard(admin_user: User = Depends(get_admin_user)):
    # Get statistics
    total_users = await db.users.count_documents({})
    total_products = await db.products.count_documents({})
    pending_products = await db.products.count_documents({"status": "pending"})
    total_purchases = await db.purchases.count_documents({})
    total_ratings = await db.ratings.count_documents({})
    
    # Recent activity
    recent_users = await db.users.find({}).sort("created_at", -1).limit(5).to_list(5)
    recent_products = await db.products.find({}).sort("created_at", -1).limit(5).to_list(5)
    recent_ratings = await db.ratings.find({}).sort("created_at", -1).limit(5).to_list(5)
    
    return {
        "stats": {
            "total_users": total_users,
            "total_products": total_products,
            "pending_products": pending_products,
            "total_purchases": total_purchases,
            "total_ratings": total_ratings
        },
        "recent_activity": {
            "users": [User(**user) for user in recent_users],
            "products": [Product(**product) for product in recent_products],
            "ratings": [Rating(**rating) for rating in recent_ratings]
        }
    }

@api_router.get("/admin/users", response_model=List[User])
async def get_all_users(admin_user: User = Depends(get_admin_user)):
    users = await db.users.find({}).to_list(1000)
    return [User(**user) for user in users]

@api_router.put("/admin/users/{user_id}")
async def update_user_status(
    user_id: str,
    status: str,  # active, banned
    role: Optional[str] = None,  # user, admin
    admin_user: User = Depends(get_admin_user)
):
    update_data = {"status": status}
    if role:
        update_data["role"] = role
    
    result = await db.users.update_one({"id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {"message": "User updated successfully"}

@api_router.get("/admin/products", response_model=List[Product])
async def get_all_products(
    status: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    query = {}
    if status:
        query["status"] = status
    
    products = await db.products.find(query).to_list(1000)
    return [Product(**product) for product in products]

@api_router.put("/admin/products/{product_id}")
async def update_product_status(
    product_id: str,
    status_update: ProductStatusUpdate,
    request: Request,
    admin_user: User = Depends(get_admin_user)
):
    # Validate status
    if status_update.status not in ["pending", "approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be pending, approved, or rejected")
    
    # If rejecting, rejection reason is required
    if status_update.status == "rejected" and not status_update.rejection_reason:
        raise HTTPException(status_code=400, detail="Rejection reason is required when rejecting a product")
    
    # Get the product first to log the change
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Prepare update data
    update_data = {"status": status_update.status}
    if status_update.status == "rejected":
        update_data["rejection_reason"] = status_update.rejection_reason
    elif status_update.status == "approved":
        # Clear rejection reason when approving
        update_data["rejection_reason"] = ""
    
    # Update the product
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Log the activity
    action_details = f"Product '{product['title']}' status changed from '{product['status']}' to '{status_update.status}'"
    if status_update.status == "rejected":
        action_details += f" with reason: {status_update.rejection_reason}"
    
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="product_status_updated",
        details=action_details,
        target_id=product_id,
        target_type="product",
        request=request
    )
    
    # Create notification for the seller
    notification_type = "success" if status_update.status == "approved" else "error"
    notification_title = f"Product {status_update.status.title()}"
    
    if status_update.status == "approved":
        notification_message = f"Your product '{product['title']}' has been approved and is now available for purchase."
    elif status_update.status == "rejected":
        notification_message = f"Your product '{product['title']}' has been rejected. Reason: {status_update.rejection_reason}"
    else:
        notification_message = f"Your product '{product['title']}' status has been updated to {status_update.status}."
    
    await create_notification_helper(
        user_id=product["seller_id"],
        title=notification_title,
        message=notification_message,
        notification_type=notification_type,
        action_url=f"/seller/my-products",
        metadata={
            "product_id": product_id,
            "product_title": product["title"],
            "status": status_update.status,
            "rejection_reason": status_update.rejection_reason if status_update.status == "rejected" else None
        }
    )
    
    return {"message": "Product status updated successfully", "status": status_update.status}

@api_router.put("/admin/products/{product_id}/edit")
async def edit_product(
    product_id: str,
    product_data: ProductEdit,
    admin_user: User = Depends(get_admin_user)
):
    # Get the current product
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Build update data with only non-None values
    update_data = {k: v for k, v in product_data.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")
    
    # Add updated timestamp
    update_data["updated_at"] = datetime.utcnow()
    
    # Update the product
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")
    
    # Return updated product
    updated_product = await db.products.find_one({"id": product_id})
    return Product(**updated_product)

@api_router.delete("/admin/products/{product_id}")
async def delete_product(
    product_id: str,
    admin_user: User = Depends(get_admin_user)
):
    # Get product to delete file
    product = await db.products.find_one({"id": product_id})
    if product:
        # Delete file
        file_path = UPLOAD_DIR / product["file_name"]
        if file_path.exists():
            os.unlink(file_path)
        
        # Delete from database
        await db.products.delete_one({"id": product_id})
        await db.ratings.delete_many({"product_id": product_id})
        
        return {"message": "Product deleted successfully"}
    
    raise HTTPException(status_code=404, detail="Product not found")

@api_router.get("/admin/ratings", response_model=List[Rating])
async def get_all_ratings(admin_user: User = Depends(get_admin_user)):
    ratings = await db.ratings.find({}).to_list(1000)
    return [Rating(**rating) for rating in ratings]

@api_router.delete("/admin/ratings/{rating_id}")
async def delete_rating(
    rating_id: str,
    admin_user: User = Depends(get_admin_user)
):
    rating = await db.ratings.find_one({"id": rating_id})
    if not rating:
        raise HTTPException(status_code=404, detail="Rating not found")
    
    await db.ratings.delete_one({"id": rating_id})
    
    # Update product rating average
    await update_product_rating(rating["product_id"])
    
    return {"message": "Rating deleted successfully"}

# Admin account creation
@api_router.post("/admin/create-admin", response_model=dict)
async def create_admin_account(
    admin_data: UserCreate,
    current_user: Optional[User] = Depends(get_current_user_optional_new)
):
    """Create admin account - only allowed if no admin exists or by existing admin"""
    
    # Check if any admin exists
    existing_admin = await db.users.find_one({"role": "admin"})
    
    # Allow creation if no admin exists (initial setup) or if current user is admin
    if existing_admin and (not current_user or current_user.role != "admin"):
        raise HTTPException(
            status_code=403, 
            detail="Admin account already exists. Only existing admins can create new admin accounts."
        )
    
    # Check if user already exists
    existing_user = await db.users.find_one({
        "$or": [{"email": admin_data.email}, {"username": admin_data.username}]
    })
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    # Create admin user
    hashed_password = hash_password(admin_data.password)
    admin_dict = admin_data.dict()
    admin_dict.pop("password")
    admin_dict["hashed_password"] = hashed_password
    admin_dict["user_type"] = "buyer"  # Can be buyer or seller
    admin_dict["role"] = "admin"  # Set as admin
    
    user_obj = User(**{k: v for k, v in admin_dict.items() if k != "hashed_password"})
    user_doc = user_obj.dict()
    user_doc["hashed_password"] = hashed_password
    await db.users.insert_one(user_doc)
    
    # Log the admin creation
    await log_activity(
        action="admin_created",
        user_id=user_obj.id,
        username=user_obj.username,
        details=f"Admin account created: {admin_data.username} ({admin_data.email})",
        target_id=user_obj.id,
        target_type="user"
    )
    
    return {
        "message": "Admin account created successfully",
        "admin_id": user_obj.id,
        "username": admin_data.username,
        "email": admin_data.email
    }

@api_router.get("/admin/setup-status")
async def get_admin_setup_status():
    """Check if initial admin setup is needed"""
    admin_count = await db.users.count_documents({"role": "admin"})
    return {
        "needs_setup": admin_count == 0,
        "admin_exists": admin_count > 0,
        "admin_count": admin_count
    }

# Notification endpoints
@api_router.get("/notifications", response_model=List[Notification])
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

@api_router.get("/notifications/unread-count")
async def get_unread_notifications_count(current_user: User = Depends(get_current_user)):
    """Get count of unread notifications for the current user"""
    count = await db.notifications.count_documents({"user_id": current_user.id, "read": False})
    return {"unread_count": count}

@api_router.put("/notifications/{notification_id}/mark-read")
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

@api_router.put("/notifications/mark-all-read")
async def mark_all_notifications_as_read(current_user: User = Depends(get_current_user)):
    """Mark all notifications as read for the current user"""
    result = await db.notifications.update_many(
        {"user_id": current_user.id, "read": False},
        {"$set": {"read": True, "read_at": datetime.utcnow()}}
    )
    
    return {"message": f"Marked {result.modified_count} notifications as read"}

@api_router.post("/notifications", response_model=Notification)
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

# Helper function to create notifications for various events
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

# Helper function to notify all admin users
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

# Bookmarks endpoints
@api_router.get("/bookmarks")
async def get_user_bookmarks(current_user: User = Depends(get_current_user)):
    """Get user's bookmarked products and sellers"""
    try:
        # Get bookmarked products
        bookmarked_products = []
        if hasattr(current_user, 'bookmarked_products') and current_user.bookmarked_products:
            for product_id in current_user.bookmarked_products:
                product = await db.products.find_one({"id": product_id, "status": "approved"})
                if product:
                    # Convert MongoDB document to JSON-serializable format
                    product_data = {
                        "id": product["id"],
                        "title": product["title"],
                        "description": product["description"],
                        "price": product["price"],
                        "category": product["category"],
                        "seller_id": product["seller_id"],
                        "seller_name": product["seller_name"],
                        "image": product.get("image"),
                        "file_size": product.get("file_size", 0),
                        "downloads": product.get("downloads", 0),
                        "rating_average": product.get("rating_average", 0),
                        "rating_count": product.get("rating_count", 0),
                        "created_at": product["created_at"],
                        "status": product["status"]
                    }
                    bookmarked_products.append(product_data)
        
        # Get bookmarked sellers
        bookmarked_sellers = []
        if hasattr(current_user, 'bookmarked_sellers') and current_user.bookmarked_sellers:
            for seller_id in current_user.bookmarked_sellers:
                seller = await db.users.find_one({"id": seller_id, "user_type": "seller"})
                if seller:
                    # Remove sensitive data and ensure JSON serializable
                    seller_data = {
                        "id": seller["id"],
                        "username": seller["username"],
                        "avatar": seller.get("avatar"),
                        "bio": seller.get("bio"),
                        "skills": seller.get("skills", []),
                        "user_type": seller["user_type"]
                    }
                    bookmarked_sellers.append(seller_data)
        
        return {
            "products": bookmarked_products,
            "sellers": bookmarked_sellers
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get bookmarks: {str(e)}")

@api_router.post("/bookmarks/{item_id}")
async def add_bookmark(
    item_id: str, 
    bookmark_type: str,  # 'product' or 'seller'
    current_user: User = Depends(get_current_user)
):
    """Add item to user's bookmarks"""
    try:
        if bookmark_type == 'product':
            # Check if product exists and is approved
            product = await db.products.find_one({"id": item_id, "status": "approved"})
            if not product:
                raise HTTPException(status_code=404, detail="Product not found")
            
            # Add to user's bookmarked products
            update_result = await db.users.update_one(
                {"id": current_user.id},
                {"$addToSet": {"bookmarked_products": item_id}}
            )
            
        elif bookmark_type == 'seller':
            # Check if seller exists
            seller = await db.users.find_one({"id": item_id, "user_type": "seller"})
            if not seller:
                raise HTTPException(status_code=404, detail="Seller not found")
            
            # Don't allow bookmarking yourself
            if item_id == current_user.id:
                raise HTTPException(status_code=400, detail="Cannot bookmark yourself")
            
            # Add to user's bookmarked sellers
            update_result = await db.users.update_one(
                {"id": current_user.id},
                {"$addToSet": {"bookmarked_sellers": item_id}}
            )
        else:
            raise HTTPException(status_code=400, detail="Invalid bookmark type")
        
        if update_result.modified_count == 0:
            return {"message": f"{bookmark_type.capitalize()} already bookmarked"}
        
        return {"message": f"{bookmark_type.capitalize()} bookmarked successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add bookmark: {str(e)}")

@api_router.delete("/bookmarks/{item_id}")
async def remove_bookmark(
    item_id: str,
    type: str,  # 'products' or 'sellers' 
    current_user: User = Depends(get_current_user)
):
    """Remove item from user's bookmarks"""
    try:
        if type == 'products':
            field_name = "bookmarked_products"
        elif type == 'sellers':
            field_name = "bookmarked_sellers"
        else:
            raise HTTPException(status_code=400, detail="Invalid bookmark type")
        
        # Remove from user's bookmarks
        update_result = await db.users.update_one(
            {"id": current_user.id},
            {"$pull": {field_name: item_id}}
        )
        
        if update_result.modified_count == 0:
            return {"message": f"{type.rstrip('s').capitalize()} was not bookmarked"}
        
        return {"message": f"{type.rstrip('s').capitalize()} removed from bookmarks"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to remove bookmark: {str(e)}")

# User logs endpoints (Admin only)
@api_router.get("/admin/users/{user_id}/logs")
async def get_user_logs(
    user_id: str,
    limit: int = 50,
    admin_user: User = Depends(get_admin_user)
):
    """Get activity logs for a specific user (Admin only)"""
    try:
        # Check if user exists
        user = await db.users.find_one({"id": user_id})
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Get user logs from activity_logs collection
        logs_cursor = db.activity_logs.find({"user_id": user_id}).sort("timestamp", -1).limit(limit)
        logs = await logs_cursor.to_list(limit)
        
        return logs
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get user logs: {str(e)}")

@api_router.delete("/admin/logs/{log_id}")
async def delete_user_log(
    log_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a specific user log (Admin only)"""
    try:
        result = await db.activity_logs.delete_one({"id": log_id})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Log not found")
        
        return {"message": "Log deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to delete log: {str(e)}")

@api_router.put("/admin/logs/{log_id}")
async def edit_user_log(
    log_id: str,
    log_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Edit a specific user log (Admin only)"""
    try:
        # Only allow editing certain fields
        allowed_fields = {"details", "notes", "admin_notes"}
        update_data = {k: v for k, v in log_data.items() if k in allowed_fields}
        
        if not update_data:
            raise HTTPException(status_code=400, detail="No valid fields to update")
        
        # Add admin modification info
        update_data["modified_by"] = admin_user.id
        update_data["modified_at"] = datetime.utcnow()
        
        result = await db.activity_logs.update_one(
            {"id": log_id},
            {"$set": update_data}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Log not found")
        
        return {"message": "Log updated successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update log: {str(e)}")

# Account deletion request endpoints
@api_router.post("/account/deletion-request")
async def create_deletion_request(
    request_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Create account deletion request"""
    try:
        reason = request_data.get("reason", "").strip()
        if not reason:
            raise HTTPException(status_code=400, detail="Deletion reason is required")
        
        # Check if user already has a pending deletion request
        existing_request = await db.deletion_requests.find_one({
            "user_id": current_user.id,
            "status": "pending"
        })
        
        if existing_request:
            raise HTTPException(status_code=400, detail="You already have a pending deletion request")
        
        # Create deletion request
        deletion_request = DeletionRequest(
            user_id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            reason=reason
        )
        
        await db.deletion_requests.insert_one(deletion_request.dict())
        
        # Update user status to pending_deletion
        await db.users.update_one(
            {"id": current_user.id},
            {"$set": {
                "status": "pending_deletion",
                "deletion_request_id": deletion_request.id
            }}
        )
        
        return {"message": "Deletion request submitted successfully", "request_id": deletion_request.id}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to create deletion request: {str(e)}")

@api_router.get("/admin/deletion-requests")
async def get_deletion_requests(
    status: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    """Get all deletion requests (Admin only)"""
    try:
        query = {}
        if status:
            query["status"] = status
        
        deletion_requests = await db.deletion_requests.find(query).sort("created_at", -1).to_list(100)
        return deletion_requests
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get deletion requests: {str(e)}")

@api_router.put("/admin/deletion-requests/{request_id}")
async def process_deletion_request(
    request_id: str,
    action_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Process deletion request - approve or reject (Admin only)"""
    try:
        action = action_data.get("action")  # approve or reject
        admin_response = action_data.get("response", "")
        
        if action not in ["approve", "reject"]:
            raise HTTPException(status_code=400, detail="Action must be 'approve' or 'reject'")
        
        # Get deletion request
        deletion_request = await db.deletion_requests.find_one({"id": request_id})
        if not deletion_request:
            raise HTTPException(status_code=404, detail="Deletion request not found")
        
        if deletion_request["status"] != "pending":
            raise HTTPException(status_code=400, detail="Request has already been processed")
        
        # Update deletion request
        await db.deletion_requests.update_one(
            {"id": request_id},
            {"$set": {
                "status": "approved" if action == "approve" else "rejected",
                "admin_response": admin_response,
                "processed_by": admin_user.id,
                "processed_at": datetime.utcnow()
            }}
        )
        
        # Update user status
        user_id = deletion_request["user_id"]
        if action == "approve":
            # Delete user account and all related data
            await db.users.delete_one({"id": user_id})
            await db.products.delete_many({"seller_id": user_id})
            await db.activity_logs.delete_many({"user_id": user_id})
            # Note: In production, you might want to anonymize rather than delete
        else:
            # Rejected - restore user to active status
            await db.users.update_one(
                {"id": user_id},
                {"$set": {
                    "status": "active",
                    "deletion_request_id": None
                }}
            )
        
        return {"message": f"Deletion request {action}d successfully"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process deletion request: {str(e)}")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()