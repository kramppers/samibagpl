from fastapi import APIRouter, Depends, HTTPException
from typing import List, Optional
from datetime import datetime

from app.models.rating import Rating, RatingCreate, RatingResponse
from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user, get_current_user_optional
from app.services.product import update_product_rating

router = APIRouter()

@router.post("/ratings", response_model=Rating)
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

@router.get("/ratings/{product_id}", response_model=List[RatingResponse])
async def get_product_ratings(product_id: str, current_user: Optional[User] = Depends(get_current_user_optional)):
    ratings = await db.ratings.find({"product_id": product_id}).to_list(100)

    result = []
    for rating_data in ratings:
        rating = Rating(**rating_data)
        can_edit = current_user and current_user.id == rating.user_id
        result.append(RatingResponse(rating=rating, can_edit=can_edit))

    return result

@router.put("/ratings/{rating_id}", response_model=Rating)
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
