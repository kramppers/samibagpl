from fastapi import APIRouter, Depends, HTTPException, Request, File, UploadFile
from typing import List, Optional
import shutil
import os
import base64
from datetime import datetime

from app.models.user import User, UserProfileUpdate, PublicProfile, PasswordChangeRequest, EmailChangeRequest, ProfileComment, ProfileCommentCreate
from app.db.session import db
from app.services.auth import (
    get_current_user,
    get_current_user_optional,
    verify_password,
    hash_password,
)
from app.services.log import log_activity
from app.core.config import settings

router = APIRouter()

@router.get("/auth/me", response_model=User)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@router.put("/profile", response_model=User)
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

@router.post("/profile/avatar")
async def upload_avatar(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="File must be an image")

    # Save avatar file
    file_extension = file.filename.split('.')[-1] if '.' in file.filename else 'jpg'
    avatar_filename = f"avatar_{current_user.id}.{file_extension}"
    avatar_path = settings.UPLOAD_DIR / "avatars"
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

@router.get("/profile/{user_id}", response_model=PublicProfile)
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

@router.get("/sellers", response_model=List[PublicProfile])
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

@router.get("/profiles", response_model=List[PublicProfile])
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

@router.get("/profile/{user_id}/purchases")
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

@router.put("/settings/password")
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

@router.put("/settings/email")
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

@router.post("/profile-comments", response_model=ProfileComment)
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

@router.get("/profile-comments/{profile_id}", response_model=List[ProfileComment])
async def get_profile_comments(profile_id: str):
    # Check if the profile exists
    profile_user = await db.users.find_one({"id": profile_id})
    if not profile_user:
        raise HTTPException(status_code=404, detail="Profile not found")

    comments = await db.profile_comments.find({"profile_id": profile_id}).sort("created_at", -1).to_list(100)
    return [ProfileComment(**comment) for comment in comments]

@router.put("/profile-comments/{comment_id}", response_model=ProfileComment)
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

@router.delete("/profile-comments/{comment_id}")
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
