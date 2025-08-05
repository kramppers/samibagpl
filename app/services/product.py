from app.db.session import db

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
