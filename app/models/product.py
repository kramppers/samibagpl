from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

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
