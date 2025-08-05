from fastapi import APIRouter, Depends, HTTPException, Request
from typing import List, Optional
import uuid
from datetime import datetime

from app.models.ticket import Ticket, TicketCreate, TicketUpdate, KnowledgeBaseArticle, TicketTemplate, TicketActivity
from app.models.user import User
from app.db.session import db
from app.services.auth import get_current_user
from app.services.log import log_activity
from app.services.notification import notify_all_admins

router = APIRouter()

@router.post("/tickets", response_model=Ticket)
async def create_ticket(
    request: Request,
    ticket_data: TicketCreate,
    current_user: User = Depends(get_current_user)
):
    """Create a new support ticket with enhanced features"""
    # Validate ticket type and priority
    valid_types = ["general", "payment_problem", "account_deletion", "technical_issue", "billing", "other"]
    valid_priorities = ["low", "medium", "high", "critical"]
    valid_severities = ["normal", "high", "critical"]

    if ticket_data.ticket_type not in valid_types:
        raise HTTPException(status_code=400, detail="Invalid ticket type")

    if ticket_data.priority not in valid_priorities:
        raise HTTPException(status_code=400, detail="Invalid priority level")

    if ticket_data.severity and ticket_data.severity not in valid_severities:
        raise HTTPException(status_code=400, detail="Invalid severity level")

    # Create ticket with enhanced features
    ticket_dict = ticket_data.dict()
    ticket_dict["user_id"] = current_user.id
    ticket_dict["username"] = current_user.username
    ticket_dict["email"] = current_user.email

    # Initialize activity history
    initial_activity = TicketActivity(
        actor=current_user.username,
        action="created",
        details=f"Ticket created with {ticket_data.priority} priority",
        new_value="open"
    )
    ticket_dict["activity_history"] = [initial_activity.dict()]

    ticket_obj = Ticket(**ticket_dict)
    await db.tickets.insert_one(ticket_obj.dict())

    # Log activity
    await log_activity(
        user_id=current_user.id,
        username=current_user.username,
        action="ticket_created",
        details=f"Created {ticket_data.priority} priority {ticket_data.ticket_type} ticket: {ticket_data.subject}",
        target_id=ticket_obj.id,
        target_type="ticket",
        request=request
    )

    # Notify all admins about the new ticket
    try:
        await notify_all_admins(
            title="New Support Ticket Created",
            message=f"User {current_user.username} created a {ticket_data.priority} priority {ticket_data.ticket_type} ticket: {ticket_data.subject}",
            notification_type="info",
            action_url=f"/admin/tickets",
            metadata={
                "ticket_id": ticket_obj.id,
                "user_id": current_user.id,
                "priority": ticket_data.priority,
                "type": ticket_data.ticket_type
            }
        )
    except Exception as e:
        print(f"Failed to notify admins about new ticket: {e}")

    return ticket_obj

@router.get("/my-tickets", response_model=List[Ticket])
async def get_my_tickets(current_user: User = Depends(get_current_user)):
    """Get current user's tickets"""
    tickets = await db.tickets.find({"user_id": current_user.id}).sort("created_at", -1).to_list(100)
    return [Ticket(**ticket) for ticket in tickets]

@router.get("/tickets/{ticket_id}", response_model=Ticket)
async def get_ticket(
    ticket_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get a specific ticket (user can only access their own tickets unless admin)"""
    ticket = await db.tickets.find_one({"id": ticket_id})
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # Check if user can access this ticket
    if ticket["user_id"] != current_user.id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="You can only access your own tickets")

    return Ticket(**ticket)

@router.get("/knowledge-base", response_model=List[KnowledgeBaseArticle])
async def get_knowledge_base_articles(
    category: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    skip: int = 0
):
    """Get knowledge base articles with optional filtering"""
    query = {"status": "published"}

    if category:
        query["category"] = category

    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"content": {"$regex": search, "$options": "i"}},
            {"summary": {"$regex": search, "$options": "i"}},
            {"tags": {"$in": [search]}}
        ]

    articles = await db.knowledge_base.find(query).sort("helpful_votes", -1).skip(skip).limit(limit).to_list(limit)
    return [KnowledgeBaseArticle(**article) for article in articles]

@router.get("/knowledge-base/search-suggestions")
async def get_knowledge_base_suggestions(
    query: str,
    ticket_type: Optional[str] = None,
    limit: int = 5
):
    """Get knowledge base article suggestions based on ticket content"""
    search_query = {
        "status": "published",
        "$or": [
            {"title": {"$regex": query, "$options": "i"}},
            {"content": {"$regex": query, "$options": "i"}},
            {"summary": {"$regex": query, "$options": "i"}},
            {"tags": {"$in": [query]}}
        ]
    }

    if ticket_type:
        search_query["$or"].append({"category": ticket_type})

    articles = await db.knowledge_base.find(search_query).sort("helpful_votes", -1).limit(limit).to_list(limit)

    return [
        {
            "id": article["id"],
            "title": article["title"],
            "summary": article["summary"],
            "category": article.get("category", ""),
            "helpful_votes": article.get("helpful_votes", 0)
        }
        for article in articles
    ]

@router.get("/knowledge-base/{article_id}", response_model=KnowledgeBaseArticle)
async def get_knowledge_base_article(article_id: str):
    """Get a specific knowledge base article and increment view count"""
    article = await db.knowledge_base.find_one({"id": article_id, "status": "published"})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Increment view count
    await db.knowledge_base.update_one(
        {"id": article_id},
        {"$inc": {"views": 1}}
    )

    article["views"] = article.get("views", 0) + 1
    return KnowledgeBaseArticle(**article)

@router.post("/knowledge-base/{article_id}/vote")
async def vote_on_article(
    article_id: str,
    helpful: bool,
    current_user: User = Depends(get_current_user)
):
    """Vote on whether an article was helpful"""
    article = await db.knowledge_base.find_one({"id": article_id})
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")

    # Check if user already voted
    existing_vote = await db.article_votes.find_one({"article_id": article_id, "user_id": current_user.id})
    if existing_vote:
        raise HTTPException(status_code=400, detail="You have already voted on this article")

    # Record vote
    vote_data = {
        "id": str(uuid.uuid4()),
        "article_id": article_id,
        "user_id": current_user.id,
        "helpful": helpful,
        "created_at": datetime.utcnow()
    }
    await db.article_votes.insert_one(vote_data)

    # Update article vote counts
    if helpful:
        await db.knowledge_base.update_one({"id": article_id}, {"$inc": {"helpful_votes": 1}})
    else:
        await db.knowledge_base.update_one({"id": article_id}, {"$inc": {"not_helpful_votes": 1}})

    return {"message": "Vote recorded successfully"}

@router.get("/ticket-templates", response_model=List[TicketTemplate])
async def get_ticket_templates(ticket_type: Optional[str] = None):
    """Get ticket templates"""
    query = {}
    if ticket_type:
        query["ticket_type"] = ticket_type

    templates = await db.ticket_templates.find(query).to_list(100)
    return [TicketTemplate(**template) for template in templates]

@router.get("/ticket-categories")
async def get_ticket_categories():
    """Get available ticket categories for better organization"""
    categories = [
        {"value": "account", "label": "Account Issues", "icon": "👤"},
        {"value": "payment", "label": "Payment & Billing", "icon": "💳"},
        {"value": "technical", "label": "Technical Support", "icon": "🔧"},
        {"value": "product", "label": "Product Issues", "icon": "📦"},
        {"value": "feedback", "label": "Feedback & Suggestions", "icon": "💭"},
        {"value": "security", "label": "Security Concerns", "icon": "🔒"},
        {"value": "legal", "label": "Legal & Compliance", "icon": "⚖️"},
        {"value": "other", "label": "Other", "icon": "❓"}
    ]

    return categories
