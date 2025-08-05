from fastapi import APIRouter, Depends, HTTPException
from typing import List

from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user

router = APIRouter()

@router.get("/bookmarks")
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

@router.post("/bookmarks/{item_id}")
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

@router.delete("/bookmarks/{item_id}")
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
