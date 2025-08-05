from fastapi import APIRouter, Depends, HTTPException, Query, Request
from typing import List, Optional
from datetime import datetime, timedelta

from app.models.user import User, UserCreate, CustomRole, CustomRoleCreate, UserTypeUpdate, AssignCustomRole
from app.models.log import ActivityLog
from app.models.seller_application import SellerApplication, SellerApplicationQuestion, SellerApplicationQuestionCreate, SellerApplicationQuestionUpdate, QuestionReorderRequest
from app.models.ticket import Ticket, TicketUpdate, KnowledgeBaseArticle, TicketTemplate
from app.models.product import Product, ProductEdit, ProductStatusUpdate
from app.models.rating import Rating
from app.models.payment import DebugPurchaseRequest
from app.db.session import db
from app.services.auth import get_admin_user, get_current_user_optional_new, hash_password
from app.services.log import log_activity
from app.services.user import check_and_unban_expired_users
from app.services.product import update_product_rating
from app.services.notification import create_notification_helper
from app.core.config import settings
import os

router = APIRouter()

@router.get("/admin/users", response_model=List[User])
async def get_all_users(admin_user: User = Depends(get_admin_user)):
    users = await db.users.find({}).to_list(1000)
    return [User(**user) for user in users]

@router.put("/admin/users/{user_id}")
async def update_user_status(
    user_id: str,
    status: str,  # active, banned
    role: Optional[str] = None,  # user, admin
    admin_user: User = Depends(get_admin_user)
):
    update_data = {"status": status}
    if role:
        update_data["role"] = role

    result = await db.users.update_one({"id": user_id}, {"$set": update_data})
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")

    return {"message": "User updated successfully"}

@router.put("/admin/users/{user_id}/manage")
async def admin_manage_user_profile(
    user_id: str,
    action: str,  # ban, unban, promote, demote, make_seller, remove_seller
    reason: Optional[str] = None,  # For ban action
    ban_type: Optional[str] = None,  # permanent, temporary
    ban_duration_days: Optional[int] = None,  # For temporary bans
    admin_user: User = Depends(get_admin_user)
):
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    update_data = {}

    if action == "ban":
        if not ban_type or ban_type not in ["permanent", "temporary"]:
            raise HTTPException(status_code=400, detail="Ban type must be 'permanent' or 'temporary'")

        update_data["status"] = "banned"
        update_data["ban_reason"] = reason or "No reason provided"
        update_data["ban_time"] = datetime.utcnow()
        update_data["ban_type"] = ban_type

        if ban_type == "temporary":
            if not ban_duration_days or ban_duration_days <= 0:
                raise HTTPException(status_code=400, detail="Temporary ban requires valid duration in days")
            update_data["ban_expires_at"] = datetime.utcnow() + timedelta(days=ban_duration_days)
        else:
            update_data["ban_expires_at"] = None

    elif action == "unban":
        update_data["status"] = "active"
        update_data["ban_reason"] = ""
        update_data["ban_time"] = None
        update_data["ban_type"] = None
        update_data["ban_expires_at"] = None
    elif action == "promote":
        update_data["role"] = "admin"
    elif action == "demote":
        update_data["role"] = "user"
    elif action == "make_seller":
        update_data["user_type"] = "seller"
    elif action == "remove_seller":
        update_data["user_type"] = "buyer"
    else:
        raise HTTPException(status_code=400, detail="Invalid action")

    await db.users.update_one({"id": user_id}, {"$set": update_data})

    return {"message": f"User {action} action completed successfully"}

@router.put("/admin/users/{user_id}/notes")
async def update_admin_notes(
    user_id: str,
    notes: str,
    admin_user: User = Depends(get_admin_user)
):
    """Update admin notes for a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await db.users.update_one(
        {"id": user_id},
        {"$set": {"admin_notes": notes}}
    )

    # Log the admin note update
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="admin_notes_updated",
        details=f"Updated admin notes for user {user['username']}",
        target_id=user_id,
        target_type="user"
    )

    return {"message": "Admin notes updated successfully"}

@router.get("/admin/users/{user_id}/notes")
async def get_admin_notes(
    user_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Get admin notes for a user"""
    user = await db.users.find_one({"id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return {"admin_notes": user.get("admin_notes", "")}

@router.get("/admin/users/search")
async def search_users(
    query: str = Query(..., min_length=1),
    limit: int = Query(20, le=100),
    admin_user: User = Depends(get_admin_user)
):
    """Search users by username or email"""
    search_query = {
        "$or": [
            {"username": {"$regex": query, "$options": "i"}},
            {"email": {"$regex": query, "$options": "i"}}
        ]
    }

    users = await db.users.find(search_query).limit(limit).to_list(limit)

    # Remove sensitive data and MongoDB ObjectId
    safe_users = []
    for user in users:
        safe_user = {k: v for k, v in user.items() if k not in ["hashed_password", "_id"]}
        safe_users.append(safe_user)

    return safe_users

@router.get("/admin/logs", response_model=List[ActivityLog])
async def get_activity_logs(
    action: Optional[str] = None,
    user_id: Optional[str] = None,
    username: Optional[str] = None,
    target_type: Optional[str] = None,
    limit: int = Query(100, le=1000),
    skip: int = Query(0, ge=0),
    admin_user: User = Depends(get_admin_user)
):
    """Get activity logs with optional filtering"""
    query = {}

    if action:
        query["action"] = action
    if user_id:
        query["user_id"] = user_id
    if username:
        query["username"] = {"$regex": username, "$options": "i"}
    if target_type:
        query["target_type"] = target_type

    logs = await db.activity_logs.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [ActivityLog(**log) for log in logs]

@router.get("/admin/logs/stats")
async def get_logs_stats(admin_user: User = Depends(get_admin_user)):
    """Get statistics about activity logs"""
    pipeline = [
        {
            "$group": {
                "_id": "$action",
                "count": {"$sum": 1}
            }
        },
        {
            "$sort": {"count": -1}
        }
    ]

    stats = await db.activity_logs.aggregate(pipeline).to_list(100)
    total_logs = await db.activity_logs.count_documents({})

    return {
        "total_logs": total_logs,
        "action_stats": stats
    }

@router.post("/admin/seller-application-questions", response_model=SellerApplicationQuestion)
async def create_seller_application_question(
    question_data: SellerApplicationQuestionCreate,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new seller application question"""
    # Get the next order number
    last_question = await db.seller_questions.find({}).sort("order", -1).limit(1).to_list(1)
    next_order = (last_question[0]["order"] + 1) if last_question else 1

    question_dict = question_data.dict()
    question_dict["order"] = next_order

    question_obj = SellerApplicationQuestion(**question_dict)
    await db.seller_questions.insert_one(question_obj.dict())

    return question_obj

@router.put("/admin/seller-application-questions/{question_id}", response_model=SellerApplicationQuestion)
async def update_seller_application_question(
    question_id: str,
    question_data: SellerApplicationQuestionUpdate,
    admin_user: User = Depends(get_admin_user)
):
    """Update a seller application question"""
    question = await db.seller_questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    update_data = {k: v for k, v in question_data.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")

    await db.seller_questions.update_one({"id": question_id}, {"$set": update_data})

    updated_question = await db.seller_questions.find_one({"id": question_id})
    return SellerApplicationQuestion(**updated_question)

@router.delete("/admin/seller-application-questions/{question_id}")
async def delete_seller_application_question(
    question_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a seller application question"""
    question = await db.seller_questions.find_one({"id": question_id})
    if not question:
        raise HTTPException(status_code=404, detail="Question not found")

    await db.seller_questions.delete_one({"id": question_id})

    # Reorder remaining questions
    remaining_questions = await db.seller_questions.find({}).sort("order", 1).to_list(100)
    for i, q in enumerate(remaining_questions, 1):
        await db.seller_questions.update_one({"id": q["id"]}, {"$set": {"order": i}})

    return {"message": "Question deleted successfully"}

@router.put("/admin/seller-application-questions/reorder")
async def reorder_seller_application_questions(
    request_data: QuestionReorderRequest,
    admin_user: User = Depends(get_admin_user)
):
    """Reorder seller application questions"""
    # Verify all questions exist first
    for question_id in request_data.question_ids:
        question = await db.seller_questions.find_one({"id": question_id})
        if not question:
            raise HTTPException(status_code=404, detail=f"Question with id {question_id} not found")

    # Update the order
    for i, question_id in enumerate(request_data.question_ids, 1):
        result = await db.seller_questions.update_one({"id": question_id}, {"$set": {"order": i}})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail=f"Question with id {question_id} not found")

    return {"message": "Questions reordered successfully"}

@router.get("/admin/tickets", response_model=List[Ticket])
async def get_all_tickets(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    ticket_type: Optional[str] = None,
    limit: int = Query(100, le=500),
    skip: int = Query(0, ge=0),
    admin_user: User = Depends(get_admin_user)
):
    """Get all tickets with optional filtering"""
    query = {}

    if status:
        query["status"] = status
    if priority:
        query["priority"] = priority
    if ticket_type:
        query["ticket_type"] = ticket_type

    tickets = await db.tickets.find(query).sort("created_at", -1).skip(skip).limit(limit).to_list(limit)
    return [Ticket(**ticket) for ticket in tickets]

@router.put("/admin/tickets/{ticket_id}", response_model=Ticket)
async def update_ticket(
    ticket_id: str,
    ticket_update: TicketUpdate,
    request: Request,
    admin_user: User = Depends(get_admin_user)
):
    """Update ticket status and admin response with activity tracking"""
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    update_data = {k: v for k, v in ticket_update.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")

    # Add timestamp for updates
    update_data["updated_at"] = datetime.utcnow()

    # Track activity history
    activity_history = ticket.get("activity_history", [])

    # Record status change
    if ticket_update.status and ticket_update.status != ticket["status"]:
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="status_changed",
            details=f"Status changed from '{ticket['status']}' to '{ticket_update.status}'",
            old_value=ticket["status"],
            new_value=ticket_update.status
        ).dict())

        # Add resolved timestamp if status is being changed to resolved/closed
        if ticket_update.status in ["resolved", "closed"] and ticket["status"] not in ["resolved", "closed"]:
            update_data["resolved_at"] = datetime.utcnow()
            if not ticket.get("first_response_time"):
                update_data["first_response_time"] = datetime.utcnow()

    # Record admin response
    if ticket_update.admin_response:
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="response_added",
            details="Admin response added",
            new_value="Response provided"
        ).dict())

        if not ticket.get("first_response_time"):
            update_data["first_response_time"] = datetime.utcnow()

    # Record assignment change
    if ticket_update.assigned_to and ticket_update.assigned_to != ticket.get("assigned_to"):
        activity_history.append(TicketActivity(
            actor=admin_user.username,
            action="assigned",
            details=f"Ticket assigned to {ticket_update.assigned_to_name or ticket_update.assigned_to}",
            old_value=ticket.get("assigned_to_name", ""),
            new_value=ticket_update.assigned_to_name or ticket_update.assigned_to
        ).dict())

    update_data["activity_history"] = activity_history

    await db.tickets.update_one({"id": ticket_id}, {"$set": update_data})

    # Create notification for ticket owner if admin response was provided
    if ticket_update.admin_response:
        await create_notification_helper(
            user_id=ticket["user_id"],
            title="Support Ticket Update 📧",
            message=f"Your support ticket '{ticket['subject']}' has been updated with a response from our team.",
            notification_type="info",
            action_url="/my-tickets",
            metadata={"ticket_id": ticket_id, "subject": ticket["subject"]}
        )

    # Create notification for status changes
    if ticket_update.status and ticket_update.status != ticket["status"]:
        status_messages = {
            "resolved": "Your support ticket has been resolved! 🎉",
            "closed": "Your support ticket has been closed.",
            "in_progress": "Your support ticket is now being worked on.",
            "reopened": "Your support ticket has been reopened."
        }
        if ticket_update.status in status_messages:
            await create_notification_helper(
                user_id=ticket["user_id"],
                title="Support Ticket Status Update",
                message=f"{status_messages[ticket_update.status]} Ticket: '{ticket['subject']}'",
                notification_type="success" if ticket_update.status == "resolved" else "info",
                action_url="/my-tickets",
                metadata={"ticket_id": ticket_id, "subject": ticket["subject"], "status": ticket_update.status}
            )

    # Log activity
    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="ticket_updated",
        details=f"Updated ticket {ticket_id} - Status: {ticket_update.status or 'unchanged'}, Response: {'provided' if ticket_update.admin_response else 'none'}",
        target_id=ticket_id,
        target_type="ticket",
        request=request
    )

    # Get updated ticket
    updated_ticket = await db.tickets.find_one({"id": ticket_id})
    return Ticket(**updated_ticket)

@router.get("/admin/tickets/stats")
async def get_ticket_stats(admin_user: User = Depends(get_admin_user)):
    """Get ticket statistics for admin dashboard"""
    # Get counts by status
    status_pipeline = [
        {"$group": {"_id": "$status", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]

    # Get counts by priority
    priority_pipeline = [
        {"$group": {"_id": "$priority", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]

    # Get counts by type
    type_pipeline = [
        {"$group": {"_id": "$ticket_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]

    status_stats = await db.tickets.aggregate(status_pipeline).to_list(100)
    priority_stats = await db.tickets.aggregate(priority_pipeline).to_list(100)
    type_stats = await db.tickets.aggregate(type_pipeline).to_list(100)

    total_tickets = await db.tickets.count_documents({})

    return {
        "total_tickets": total_tickets,
        "status_stats": status_stats,
        "priority_stats": priority_stats,
        "type_stats": type_stats
    }

@router.post("/admin/knowledge-base", response_model=KnowledgeBaseArticle)
async def create_knowledge_base_article(
    article_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new knowledge base article (admin only)"""
    article_dict = {
        "id": str(uuid.uuid4()),
        "author": admin_user.username,
        "helpful_votes": 0,
        "not_helpful_votes": 0,
        "views": 0,
        "created_at": datetime.utcnow(),
        **article_data
    }

    article_obj = KnowledgeBaseArticle(**article_dict)
    await db.knowledge_base.insert_one(article_obj.dict())

    return article_obj

@router.put("/admin/knowledge-base/{article_id}", response_model=KnowledgeBaseArticle)
async def update_knowledge_base_article(
    article_id: str,
    article_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Update an existing knowledge base article (admin only)"""
    # Check if article exists
    existing_article = await db.knowledge_base.find_one({"id": article_id})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Update the article data
    update_data = {
        **article_data,
        "updated_at": datetime.utcnow()
    }

    await db.knowledge_base.update_one(
        {"id": article_id},
        {"$set": update_data}
    )

    # Get updated article
    updated_article = await db.knowledge_base.find_one({"id": article_id})
    return KnowledgeBaseArticle(**updated_article)

@router.delete("/admin/knowledge-base/{article_id}")
async def delete_knowledge_base_article(
    article_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Delete a knowledge base article (admin only)"""
    # Check if article exists
    existing_article = await db.knowledge_base.find_one({"id": article_id})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Delete the article
    result = await db.knowledge_base.delete_one({"id": article_id})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Article not found")

    return {"message": "Article deleted successfully", "article_id": article_id}

@router.get("/admin/knowledge-base/drafts", response_model=List[KnowledgeBaseArticle])
async def get_draft_articles(
    admin_user: User = Depends(get_admin_user)
):
    """Get all draft knowledge base articles (admin only)"""
    articles = await db.knowledge_base.find({"status": "draft"}).sort("created_at", -1).to_list(length=100)
    return [KnowledgeBaseArticle(**article) for article in articles]

@router.put("/admin/knowledge-base/{article_id}/publish")
async def publish_article(
    article_id: str,
    admin_user: User = Depends(get_admin_user)
):
    """Publish a draft article (admin only)"""
    # Check if article exists and is a draft
    existing_article = await db.knowledge_base.find_one({"id": article_id, "status": "draft"})
    if not existing_article:
        raise HTTPException(status_code=404, detail="Draft article not found")

    # Update article status to published
    result = await db.knowledge_base.update_one(
        {"id": article_id},
        {"$set": {"status": "published", "updated_at": datetime.utcnow()}}
    )

    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Article not found")

    return {"message": "Article published successfully", "article_id": article_id}

@router.post("/admin/ticket-templates", response_model=TicketTemplate)
async def create_ticket_template(
    template_data: dict,
    admin_user: User = Depends(get_admin_user)
):
    """Create a new ticket template (admin only)"""
    template_dict = {
        "id": str(uuid.uuid4()),
        **template_data
    }

    template_obj = TicketTemplate(**template_dict)
    await db.ticket_templates.insert_one(template_obj.dict())

    return template_obj

@router.get("/admin/seller-applications", response_model=List[SellerApplication])
async def get_seller_applications(
    status: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    query = {}
    if status:
        query["status"] = status

    applications = await db.seller_applications.find(query).to_list(100)
    return [SellerApplication(**app) for app in applications]

@router.put("/admin/seller-applications/{application_id}")
async def review_seller_application(
    application_id: str,
    status: str,  # approved, rejected
    admin_notes: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    application = await db.seller_applications.find_one({"id": application_id})
    if not application:
        raise HTTPException(status_code=404, detail="Application not found")

    # Update application status
    update_data = {
        "status": status,
        "reviewed_at": datetime.utcnow(),
        "reviewed_by": admin_user.id
    }
    if admin_notes:
        update_data["admin_notes"] = admin_notes

    await db.seller_applications.update_one(
        {"id": application_id},
        {"$set": update_data}
    )

    # If approved, update user to seller
    if status == "approved":
        await db.users.update_one(
            {"id": application["user_id"]},
            {"$set": {"user_type": "seller"}}
        )

        # Create notification for user
        await create_notification_helper(
            user_id=application["user_id"],
            title="Seller Application Approved! 🎉",
            message="Congratulations! Your seller application has been approved. You can now start selling products on our marketplace.",
            notification_type="success",
            action_url="/sell",
            metadata={"application_id": application_id}
        )
    elif status == "rejected":
        # Create notification for user
        await create_notification_helper(
            user_id=application["user_id"],
            title="Seller Application Update",
            message=f"Your seller application has been reviewed. {admin_notes or 'Please contact support for more information.'}",
            notification_type="warning",
            action_url="/apply-seller",
            metadata={"application_id": application_id, "admin_notes": admin_notes}
        )

    return {"message": "Application reviewed successfully"}

@router.post("/admin/create-admin", response_model=dict)
async def create_admin_account(
    admin_data: UserCreate,
    current_user: Optional[User] = Depends(get_current_user_optional_new)
):
    """Create admin account - only allowed if no admin exists or by existing admin"""

    # Check if any admin exists
    existing_admin = await db.users.find_one({"role": "admin"})

    # Allow creation if no admin exists (initial setup) or if current user is admin
    if existing_admin and (not current_user or current_user.role != "admin"):
        raise HTTPException(
            status_code=403,
            detail="Admin account already exists. Only existing admins can create new admin accounts."
        )

    # Check if user already exists
    existing_user = await db.users.find_one({
        "$or": [{"email": admin_data.email}, {"username": admin_data.username}]
    })
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Create admin user
    hashed_password = hash_password(admin_data.password)
    admin_dict = admin_data.dict()
    admin_dict.pop("password")
    admin_dict["hashed_password"] = hashed_password
    admin_dict["user_type"] = "buyer"  # Can be buyer or seller
    admin_dict["role"] = "admin"  # Set as admin

    user_obj = User(**{k: v for k, v in admin_dict.items() if k != "hashed_password"})
    user_doc = user_obj.dict()
    user_doc["hashed_password"] = hashed_password
    await db.users.insert_one(user_doc)

    # Log the admin creation
    await log_activity(
        action="admin_created",
        user_id=user_obj.id,
        username=user_obj.username,
        details=f"Admin account created: {admin_data.username} ({admin_data.email})",
        target_id=user_obj.id,
        target_type="user"
    )

    return {
        "message": "Admin account created successfully",
        "admin_id": user_obj.id,
        "username": admin_data.username,
        "email": admin_data.email
    }

@router.get("/admin/setup-status")
async def get_admin_setup_status():
    """Check if initial admin setup is needed"""
    admin_count = await db.users.count_documents({"role": "admin"})
    return {
        "needs_setup": admin_count == 0,
        "admin_exists": admin_count > 0,
        "admin_count": admin_count
    }

@router.post("/admin/debug-purchase")
async def debug_purchase(
    request: DebugPurchaseRequest,
    admin_user: User = Depends(get_admin_user)
):
    """
    Debug endpoint for admins to simulate product purchases without payment processing.
    Creates a purchase record directly in the database for testing purposes.
    """
    try:
        # Get product
        product = await db.products.find_one({"id": request.product_id})
        if not product:
            raise HTTPException(
                status_code=404,
                detail=f"Product with ID '{request.product_id}' not found"
            )

        # Validate product is approved and active
        if product.get("status") != "approved":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot create debug purchase for product with status '{product.get('status')}'. Product must be approved."
            )

        # Determine buyer - use provided buyer_id or admin user
        if request.buyer_id:
            # Validate buyer exists
            buyer = await db.users.find_one({"id": request.buyer_id})
            if not buyer:
                raise HTTPException(
                    status_code=404,
                    detail=f"Buyer user with ID '{request.buyer_id}' not found"
                )

            # Validate buyer is not the seller (prevent self-purchase)
            if request.buyer_id == product["seller_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot create debug purchase: buyer cannot be the same as the product seller"
                )

            actual_buyer_id = request.buyer_id
            buyer_username = buyer["username"]
        else:
            # Use admin as buyer
            buyer = admin_user
            actual_buyer_id = admin_user.id
            buyer_username = admin_user.username

        # Check if user already owns this product (duplicate purchase validation)
        existing_purchase = await db.purchases.find_one({
            "buyer_id": actual_buyer_id,
            "product_id": request.product_id
        })
        if existing_purchase:
            raise HTTPException(
                status_code=400,
                detail=f"Product '{product['title']}' has already been purchased by user '{buyer_username}'. Duplicate purchases are not allowed."
            )

        # Get seller details for validation and notifications
        seller = await db.users.find_one({"id": product["seller_id"]})
        if not seller:
            raise HTTPException(
                status_code=404,
                detail=f"Product seller with ID '{product['seller_id']}' not found"
            )

        # Generate debug session ID and download token
        debug_session_id = f"debug_{uuid.uuid4().hex[:16]}"
        download_token = hashlib.sha256(f"{debug_session_id}{request.product_id}{actual_buyer_id}".encode()).hexdigest()

        # Create debug payment transaction record
        payment_transaction = PaymentTransaction(
            session_id=debug_session_id,
            product_id=request.product_id,
            buyer_id=actual_buyer_id,
            seller_id=product["seller_id"],
            amount=product["price"],
            currency="usd",
            payment_status="paid",  # Mark as paid since this is debug mode
            stripe_status="debug_completed",
            metadata={
                "debug_mode": True,
                "admin_user": admin_user.id,
                "admin_username": admin_user.username,
                "product_id": request.product_id,
                "buyer_id": actual_buyer_id,
                "seller_id": product["seller_id"],
                "created_by": "admin_debug_endpoint"
            }
        )

        await db.payment_transactions.insert_one(payment_transaction.dict())

        # Create purchase record
        purchase = Purchase(
            buyer_id=actual_buyer_id,
            product_id=request.product_id,
            seller_id=product["seller_id"],
            transaction_id=payment_transaction.id,
            download_token=download_token
        )

        await db.purchases.insert_one(purchase.dict())

        # Create notification for buyer (if not admin)
        if actual_buyer_id != admin_user.id:
            await create_notification_helper(
                user_id=actual_buyer_id,
                title="Debug Purchase Successful! 🧪",
                message=f"Admin has created a debug purchase for '{product['title']}'. You can now access it from your purchases page.",
                notification_type="info",
                action_url="/my-purchases",
                metadata={
                    "debug_mode": True,
                    "product_id": product["id"],
                    "product_title": product["title"],
                    "admin_user": admin_user.username
                }
            )

        # Create notification for seller (if not admin)
        if seller and seller["id"] != admin_user.id:
            await create_notification_helper(
                user_id=seller["id"],
                title="Debug Sale Created! 🧪",
                message=f"Admin has created a debug purchase of your product '{product['title']}' for testing purposes.",
                notification_type="info",
                action_url="/my-products",
                metadata={
                    "debug_mode": True,
                    "product_id": product["id"],
                    "product_title": product["title"],
                    "buyer_username": buyer_username,
                    "admin_user": admin_user.username
                }
            )

        # Update product download count
        await db.products.update_one(
            {"id": request.product_id},
            {"$inc": {"downloads": 1}}
        )

        # Log activity
        await log_activity(
            user_id=admin_user.id,
            username=admin_user.username,
            action="debug_purchase_created",
            details=f"Admin {admin_user.username} created debug purchase of product '{product['title']}' for user {buyer_username}",
            target_id=purchase.id,
            target_type="purchase"
        )

        return {
            "success": True,
            "message": "Debug purchase created successfully",
            "purchase_id": purchase.id,
            "session_id": debug_session_id,
            "download_token": download_token,
            "buyer": {
                "id": actual_buyer_id,
                "username": buyer_username
            },
            "product": {
                "id": product["id"],
                "title": product["title"],
                "price": product["price"]
            },
            "seller": {
                "id": seller["id"],
                "username": seller["username"]
            },
            "debug_info": {
                "created_by": admin_user.username,
                "created_at": datetime.utcnow().isoformat()
            }
        }

    except HTTPException:
        # Re-raise HTTP exceptions as they are already properly formatted
        raise
    except Exception as e:
        # Log unexpected errors and return 500
        logger.error(f"Unexpected error in debug purchase endpoint: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error occurred while creating debug purchase: {str(e)}"
        )

@router.get("/admin/dashboard")
async def get_admin_dashboard(admin_user: User = Depends(get_admin_user)):
    # Get statistics
    total_users = await db.users.count_documents({})
    total_products = await db.products.count_documents({})
    pending_products = await db.products.count_documents({"status": "pending"})
    total_purchases = await db.purchases.count_documents({})
    total_ratings = await db.ratings.count_documents({})

    # Recent activity
    recent_users = await db.users.find({}).sort("created_at", -1).limit(5).to_list(5)
    recent_products = await db.products.find({}).sort("created_at", -1).limit(5).to_list(5)
    recent_ratings = await db.ratings.find({}).sort("created_at", -1).limit(5).to_list(5)

    return {
        "stats": {
            "total_users": total_users,
            "total_products": total_products,
            "pending_products": pending_products,
            "total_purchases": total_purchases,
            "total_ratings": total_ratings
        },
        "recent_activity": {
            "users": [User(**user) for user in recent_users],
            "products": [Product(**product) for product in recent_products],
            "ratings": [Rating(**rating) for rating in recent_ratings]
        }
    }

@router.get("/admin/products", response_model=List[Product])
async def get_all_products(
    status: Optional[str] = None,
    admin_user: User = Depends(get_admin_user)
):
    query = {}
    if status:
        query["status"] = status

    products = await db.products.find(query).to_list(1000)
    return [Product(**product) for product in products]

@router.put("/admin/products/{product_id}")
async def update_product_status(
    product_id: str,
    status_update: ProductStatusUpdate,
    request: Request,
    admin_user: User = Depends(get_admin_user)
):
    # Validate status
    if status_update.status not in ["pending", "approved", "rejected"]:
        raise HTTPException(status_code=400, detail="Invalid status. Must be pending, approved, or rejected")

    # If rejecting, rejection reason is required
    if status_update.status == "rejected" and not status_update.rejection_reason:
        raise HTTPException(status_code=400, detail="Rejection reason is required when rejecting a product")

    # Get the product first to log the change
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Prepare update data
    update_data = {"status": status_update.status}
    if status_update.status == "rejected":
        update_data["rejection_reason"] = status_update.rejection_reason
    elif status_update.status == "approved":
        # Clear rejection reason when approving
        update_data["rejection_reason"] = ""

    # Update the product
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": update_data}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")

    # Log the activity
    action_details = f"Product '{product['title']}' status changed from '{product['status']}' to '{status_update.status}'"
    if status_update.status == "rejected":
        action_details += f" with reason: {status_update.rejection_reason}"

    await log_activity(
        user_id=admin_user.id,
        username=admin_user.username,
        action="product_status_updated",
        details=action_details,
        target_id=product_id,
        target_type="product",
        request=request
    )

    # Create notification for the seller
    notification_type = "success" if status_update.status == "approved" else "error"
    notification_title = f"Product {status_update.status.title()}"

    if status_update.status == "approved":
        notification_message = f"Your product '{product['title']}' has been approved and is now available for purchase."
    elif status_update.status == "rejected":
        notification_message = f"Your product '{product['title']}' has been rejected. Reason: {status_update.rejection_reason}"
    else:
        notification_message = f"Your product '{product['title']}' status has been updated to {status_update.status}."

    await create_notification_helper(
        user_id=product["seller_id"],
        title=notification_title,
        message=notification_message,
        notification_type=notification_type,
        action_url=f"/seller/my-products",
        metadata={
            "product_id": product_id,
            "product_title": product["title"],
            "status": status_update.status,
            "rejection_reason": status_update.rejection_reason if status_update.status == "rejected" else None
        }
    )

    return {"message": "Product status updated successfully", "status": status_update.status}

@router.put("/admin/products/{product_id}/edit")
async def edit_product(
    product_id: str,
    product_data: ProductEdit,
    admin_user: User = Depends(get_admin_user)
):
    # Get the current product
    product = await db.products.find_one({"id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Build update data with only non-None values
    update_data = {k: v for k, v in product_data.dict().items() if v is not None}
    if not update_data:
        raise HTTPException(status_code=400, detail="No data provided for update")

    # Add updated timestamp
    update_data["updated_at"] = datetime.utcnow()

    # Update the product
    result = await db.products.update_one(
        {"id": product_id},
        {"$set": update_data}
    )

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Product not found")

    # Return updated product
    updated_product = await db.products.find_one({"id": product_id})
    return Product(**updated_product)

@router.delete("/admin/products/{product_id}")
async def delete_product(
    product_id: str,
    admin_user: User = Depends(get_admin_user)
):
    # Get product to delete file
    product = await db.products.find_one({"id": product_id})
    if product:
        # Delete file
        file_path = settings.UPLOAD_DIR / product["file_name"]
        if file_path.exists():
            os.unlink(file_path)

        # Delete from database
        await db.products.delete_one({"id": product_id})
        await db.ratings.delete_many({"product_id": product_id})

        return {"message": "Product deleted successfully"}

    raise HTTPException(status_code=404, detail="Product not found")

@router.get("/admin/ratings", response_model=List[Rating])
async def get_all_ratings(admin_user: User = Depends(get_admin_user)):
    ratings = await db.ratings.find({}).to_list(1000)
    return [Rating(**rating) for rating in ratings]

@router.delete("/admin/ratings/{rating_id}")
async def delete_rating(
    rating_id: str,
    admin_user: User = Depends(get_admin_user)
):
    rating = await db.ratings.find_one({"id": rating_id})
    if not rating:
        raise HTTPException(status_code=404, detail="Rating not found")

    await db.ratings.delete_one({"id": rating_id})

    # Update product rating average
    await update_product_rating(rating["product_id"])

    return {"message": "Rating deleted successfully"}

@router.get("/admin/expired-bans/check")
async def check_expired_bans(admin_user: User = Depends(get_admin_user)):
    """Manually trigger check for expired temporary bans"""
    unbanned_count = await check_and_unban_expired_users()
    return {"message": f"Checked expired bans. Unbanned {unbanned_count} users."}
