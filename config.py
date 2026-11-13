
import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Read database URL from Railway
database_url = os.environ.get(
    "DATABASE_URL",
    "sqlite:///lost_found.db"
)

# Convert Railway PostgreSQL URL for psycopg
if database_url.startswith("postgres://"):
    database_url = database_url.replace(
        "postgres://",
        "postgresql+psycopg://",
        1
    )
elif database_url.startswith("postgresql://"):
    database_url = database_url.replace(
        "postgresql://",
        "postgresql+psycopg://",
        1
    )


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = database_url
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE") == "1"

    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    REMEMBER_COOKIE_HTTPONLY = True

    ITEMS_PER_PAGE = 9

    DEFAULT_CATEGORIES = [
        "Electronics", "Wallets & Cards", "Keys", "Bags & Luggage",
        "Clothing & Accessories", "Documents & IDs", "Jewellery",
        "Pets", "Books & Stationery", "Other",
    ]
