from pydantic import BaseModel, Field
from typing import Optional
import uuid
from datetime import datetime

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

class RatingResponse(BaseModel):
    rating: Rating
    can_edit: bool = False
