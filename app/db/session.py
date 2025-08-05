from motor.motor_asyncio import AsyncIOMotorClient
from app.core.config import settings

client = AsyncIOMotorClient(settings.MONGO_URL, maxPoolSize=10, minPoolSize=10)
db = client[settings.DB_NAME]

def get_db():
    return db

def close_mongo_connection():
    client.close()
