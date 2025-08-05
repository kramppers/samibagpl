from fastapi import APIRouter, Depends, HTTPException, Request, Form, File, UploadFile
from typing import List, Optional
import shutil
import uuid
import base64

from app.models.product import Product
from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user
from app.services.log import log_activity
from app.core.config import settings

router = APIRouter()

@router.post("/products", response_model=Product)
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
    file_path = settings.UPLOAD_DIR / stored_filename

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

@router.get("/products", response_model=List[Product])
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

@router.get("/products/{product_id}", response_model=Product)
async def get_product(product_id: str):
    product = await db.products.find_one({"id": product_id, "status": "approved"})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return Product(**product)

@router.get("/my-products", response_model=List[Product])
async def get_my_products(current_user: User = Depends(get_current_user)):
    if current_user.user_type != "seller":
        raise HTTPException(status_code=403, detail="Only sellers can view their products")

    products = await db.products.find({"seller_id": current_user.id}).to_list(100)
    return [Product(**product) for product in products]
