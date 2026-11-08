from datetime import datetime, timezone

from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    phone = db.Column(db.String(20))  # private; never shown publicly
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    items = db.relationship("Item", backref="owner", lazy="dynamic",
                            cascade="all, delete-orphan")

    @property
    def is_active(self):  # Flask-Login: deactivated users cannot log in
        return self.active

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    __tablename__ = "category"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)


class Item(db.Model):
    __tablename__ = "item"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    item_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    item_type = db.Column(db.String(10), nullable=False, index=True)  # "Lost" / "Found"
    location = db.Column(db.String(150), nullable=False)
    report_date = db.Column(db.Date, nullable=False)  # date lost / found
    image = db.Column(db.String(100))
    status = db.Column(db.String(20), default="Open", nullable=False)  # Open / Returned
    # Private fields - only the owner (and admins) can read these.
    additional_info = db.Column(db.Text)
    contact_preference = db.Column(db.String(20), default="messages", nullable=False)
    flagged = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    messages = db.relationship("Message", backref="item", cascade="all, delete-orphan")
    claims = db.relationship("Claim", backref="item", cascade="all, delete-orphan",
                             order_by="Claim.created_at.desc()")


class Message(db.Model):
    __tablename__ = "message"
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False, index=True)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    sender = db.relationship("User", foreign_keys=[sender_id])
    receiver = db.relationship("User", foreign_keys=[receiver_id])


class Claim(db.Model):
    __tablename__ = "claim"
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey("item.id"), nullable=False, index=True)
    claimant_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    claim_details = db.Column(db.Text, nullable=False)  # private
    status = db.Column(db.String(20), default="Pending", nullable=False)  # Pending/Approved/Rejected
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    claimant = db.relationship("User", foreign_keys=[claimant_id])
