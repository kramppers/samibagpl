from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List

from app.models.seller_application import SellerApplication, SellerApplicationCreate
from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user
from app.services.log import log_activity
from app.services.notification import notify_all_admins

router = APIRouter()

@router.post("/seller-application", response_model=SellerApplication)
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

@router.get("/my-seller-application", response_model=SellerApplication)
async def get_my_seller_application(current_user: User = Depends(get_current_user)):
    application = await db.seller_applications.find_one({"user_id": current_user.id})
    if not application:
        raise HTTPException(status_code=404, detail="No seller application found")

    return SellerApplication(**application)
