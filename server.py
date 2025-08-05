from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware
import logging

from app.db.session import close_mongo_connection
from app.routers import auth, users, products, ratings, seller_applications, admin, tickets, notifications, payments, bookmarks
from app.core.config import settings

app = FastAPI()

# Include all the routers
app.include_router(auth.router, prefix="/api", tags=["auth"])
app.include_router(users.router, prefix="/api", tags=["users"])
app.include_router(products.router, prefix="/api", tags=["products"])
app.include_router(ratings.router, prefix="/api", tags=["ratings"])
app.include_router(seller_applications.router, prefix="/api", tags=["seller-applications"])
app.include_router(admin.router, prefix="/api", tags=["admin"])
app.include_router(tickets.router, prefix="/api", tags=["tickets"])
app.include_router(notifications.router, prefix="/api", tags=["notifications"])
app.include_router(payments.router, prefix="/api", tags=["payments"])
app.include_router(bookmarks.router, prefix="/api", tags=["bookmarks"])


app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    close_mongo_connection()