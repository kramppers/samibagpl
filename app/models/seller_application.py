from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Union
import uuid
from datetime import datetime

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
