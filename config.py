import os
from datetime import timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # SECRET_KEY: set the SECRET_KEY environment variable in production.
    # If it is missing, app.py generates one and stores it in instance/secret_key.
    SECRET_KEY = os.environ.get("SECRET_KEY")

    # Relative sqlite paths are placed in the instance/ folder by Flask-SQLAlchemy.
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///lost_found.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5 MB upload limit
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}

    # Session / cookie security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    # Set SESSION_COOKIE_SECURE=1 when serving over HTTPS.
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE") == "1"
    PERMANENT_SESSION_LIFETIME = timedelta(days=7)
    REMEMBER_COOKIE_HTTPONLY = True

    ITEMS_PER_PAGE = 9
    DEFAULT_CATEGORIES = [
        "Electronics", "Wallets & Cards", "Keys", "Bags & Luggage",
        "Clothing & Accessories", "Documents & IDs", "Jewellery",
        "Pets", "Books & Stationery", "Other",
    ]
