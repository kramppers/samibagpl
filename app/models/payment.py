from pydantic import BaseModel, Field
from typing import Optional, Dict, Any
import uuid
from datetime import datetime

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
