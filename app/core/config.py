import os
from pathlib import Path
from pydantic import BaseSettings
from dotenv import load_dotenv

# It's better to load the .env file from the root of the project
# Assuming the script is run from the project root
load_dotenv()

class Settings(BaseSettings):
    # JWT
    JWT_SECRET: str = "your-secret-key-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # MongoDB
    MONGO_URL: str
    DB_NAME: str

    # File storage
    UPLOAD_DIR: Path = Path("/app/uploads")

    # Stripe
    STRIPE_API_KEY: str

    class Config:
        case_sensitive = True

settings = Settings()
