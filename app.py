import os
import re
import secrets
import uuid
from datetime import date, datetime
from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import (Flask, abort, flash, redirect, render_template, request,
                   session, url_for)
from flask_login import (LoginManager, current_user, login_required,
                         login_user, logout_user)
from PIL import Image, ImageOps, UnidentifiedImageError
from sqlalchemy import func, or_

from config import Config
from matching import find_matches
from models import Category, Claim, Item, Message, User, db

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
PHONE_RE = re.compile(r"^[0-9+\-\s()]{7,20}$")
CONTACT_PREFS = {
    "messages": "In-app messages only",
    "phone": "Share my phone number after a verified claim",
    "email": "Share my email after a verified claim",
}

app = Flask(__name__, instance_relative_config=True)
app.config.from_object(Config)
os.makedirs(app.instance_path, exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

if not app.config.get("SECRET_KEY"):
    _kp = os.path.join(app.instance_path, "secret_key")
    if not os.path.exists(_kp):
        with open(_kp, "w") as fh:
            fh.write(secrets.token_hex(32))
    with open(_kp) as fh:
        app.config["SECRET_KEY"] = fh.read().strip()

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# ----------------------------------------------------------------- security
def get_csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.form.get("csrf_token", "")
        good = session.get("_csrf", "")
        if not good or not secrets.compare_digest(sent, good):
            abort(400)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "SAMEORIGIN"
    resp.headers["Referrer-Policy"] = "same-origin"
    return resp


@app.context_processor
def inject_globals():
    unread = 0
    if current_user.is_authenticated:
        unread = Message.query.filter_by(receiver_id=current_user.id, is_read=False).count()
    return {
        "csrf_token": get_csrf_token,
        "unread_count": unread,
        "categories": [c.name for c in Category.query.order_by(Category.name).all()],
        "contact_prefs": CONTACT_PREFS,
        "today": date.today().isoformat(),
    }


def is_safe_url(target):
    ref, test = urlparse(request.host_url), urlparse(urljoin(request.host_url, target))
    return test.scheme in ("http", "https") and ref.netloc == test.netloc


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*a, **kw):
        if not current_user.is_admin:
            abort(403)
        return view(*a, **kw)
    return wrapped


# ----------------------------------------------------------------- helpers
def parse_date(value):
    try:
        return datetime.strptime((value or "").strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def save_image(file):
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in app.config["ALLOWED_EXTENSIONS"]:
        raise ValueError("Image must be a PNG, JPG, GIF or WEBP file.")
    try:
        img = Image.open(file.stream)
        img.verify()
        file.stream.seek(0)
        img = Image.open(file.stream)
        if img.format not in ("PNG", "JPEG", "GIF", "WEBP"):
            raise ValueError
        img = ImageOps.exif_transpose(img)  # re-saving also strips EXIF/GPS data
        img.thumbnail((1200, 1200))
    except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombError):
        raise ValueError("The uploaded file is not a valid image.")
    name = uuid.uuid4().hex
    if img.mode in ("RGBA", "LA", "P"):
        name += ".png"
        img.convert("RGBA").save(os.path.join(app.config["UPLOAD_FOLDER"], name), "PNG")
    else:
        name += ".jpg"
        img.convert("RGB").save(os.path.join(app.config["UPLOAD_FOLDER"], name), "JPEG", quality=85)
    return name


def delete_image(filename):
    if filename:
        path = os.path.join(app.config["UPLOAD_FOLDER"], os.path.basename(filename))
        if os.path.exists(path):
            os.remove(path)


def can_manage(item):
    return current_user.is_authenticated and (current_user.id == item.user_id or current_user.is_admin)


def can_message(item, other_id):
    """A thread is valid between the item owner and someone who messaged or claimed."""
    uid = current_user.id
    if uid == other_id:
        return False
    if other_id == item.user_id:
        return True
    if uid == item.user_id:
        return (Message.query.filter_by(item_id=item.id, sender_id=other_id).first() is not None
                or Claim.query.filter_by(item_id=item.id, claimant_id=other_id).first() is not None)
    return False


# ----------------------------------------------------------------- public pages
@app.route("/")
def index():
    def recent(kind):
        return (Item.query.filter_by(item_type=kind, status="Open")
                .order_by(Item.created_at.desc()).limit(6).all())
    stats = {
        "users": User.query.count(),
        "lost": Item.query.filter_by(item_type="Lost").count(),
        "found": Item.query.filter_by(item_type="Found").count(),
        "returned": Item.query.filter_by(status="Returned").count(),
    }
    return render_template("index.html", lost_items=recent("Lost"),
                           found_items=recent("Found"), stats=stats)


# ----------------------------------------------------------------- auth
@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        errors = []
        if not USERNAME_RE.match(username):
            errors.append("Username must be 3-30 characters: letters, numbers, . _ -")
        if not EMAIL_RE.match(email) or len(email) > 120:
            errors.append("Enter a valid email address.")
        if phone and not PHONE_RE.match(phone):
            errors.append("Enter a valid phone number or leave it blank.")
        if len(pw) < 8 or not re.search(r"[A-Za-z]", pw) or not re.search(r"\d", pw):
            errors.append("Password must be at least 8 characters with a letter and a number.")
        if pw != pw2:
            errors.append("Passwords do not match.")
        if not errors:
            if User.query.filter(func.lower(User.username) == username.lower()).first():
                errors.append("That username is taken.")
            if User.query.filter_by(email=email).first():
                errors.append("That email is already registered.")
        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("register.html", form=request.form)
        user = User(username=username, email=email, phone=phone or None)
        user.set_password(pw)
        db.session.add(user)
        db.session.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        ident = request.form.get("identifier", "").strip()
        user = User.query.filter(or_(func.lower(User.username) == ident.lower(),
                                     User.email == ident.lower())).first()
        
        password = request.form.get("password", "")

        print("USER FOUND:", user is not None)
        print("ACCOUNT ACTIVE:", user.active if user else None)
        print("PASSWORD MATCH:", user.check_password(password) if user else None)

        if user and user.check_password(password):

            if not user.active:
                flash("This account has been deactivated.", "danger")
                return render_template("login.html")
            session.clear()
            login_user(user)
            session.permanent = True
            nxt = request.args.get("next")
            return redirect(nxt if nxt and is_safe_url(nxt) else url_for("dashboard"))
        flash("Invalid username/email or password.", "danger")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "details":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            errors = []
            if not USERNAME_RE.match(username):
                errors.append("Username must be 3-30 characters: letters, numbers, . _ -")
            if not EMAIL_RE.match(email):
                errors.append("Enter a valid email address.")
            if phone and not PHONE_RE.match(phone):
                errors.append("Enter a valid phone number or leave it blank.")
            if not errors:
                if User.query.filter(func.lower(User.username) == username.lower(),
                                     User.id != current_user.id).first():
                    errors.append("That username is taken.")
                if User.query.filter(User.email == email, User.id != current_user.id).first():
                    errors.append("That email is already registered.")
            if errors:
                for e in errors:
                    flash(e, "danger")
            else:
                current_user.username, current_user.email = username, email
                current_user.phone = phone or None
                db.session.commit()
                flash("Profile updated.", "success")
        elif action == "password":
            cur, new, conf = (request.form.get(k, "") for k in ("current", "new", "confirm"))
            if not current_user.check_password(cur):
                flash("Current password is incorrect.", "danger")
            elif len(new) < 8 or not re.search(r"[A-Za-z]", new) or not re.search(r"\d", new):
                flash("New password must be at least 8 characters with a letter and a number.", "danger")
            elif new != conf:
                flash("New passwords do not match.", "danger")
            else:
                current_user.set_password(new)
                db.session.commit()
                flash("Password changed.", "success")
        return redirect(url_for("profile"))
    stats = {
        "reports": current_user.items.count(),
        "returned": current_user.items.filter_by(status="Returned").count(),
    }
    return render_template("profile.html", stats=stats)


# ----------------------------------------------------------------- dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    tab = request.args.get("tab", "all")
    q = Item.query
    if tab == "lost":
        q = q.filter_by(item_type="Lost")
    elif tab == "found":
        q = q.filter_by(item_type="Found")
    elif tab == "mine":
        q = q.filter_by(user_id=current_user.id)
    search = request.args.get("q", "").strip()
    category = request.args.get("category", "").strip()
    location = request.args.get("location", "").strip()
    status = request.args.get("status", "").strip()
    d_from, d_to = parse_date(request.args.get("date_from")), parse_date(request.args.get("date_to"))
    if search:
        q = q.filter(Item.item_name.ilike(f"%{search}%"))
    if category:
        q = q.filter_by(category=category)
    if location:
        q = q.filter(Item.location.ilike(f"%{location}%"))
    if status in ("Open", "Returned"):
        q = q.filter_by(status=status)
    if d_from:
        q = q.filter(Item.report_date >= d_from)
    if d_to:
        q = q.filter(Item.report_date <= d_to)
    page = request.args.get("page", 1, type=int)
    pagination = q.order_by(Item.created_at.desc()).paginate(
        page=page, per_page=app.config["ITEMS_PER_PAGE"], error_out=False)
    qargs = {k: v for k, v in request.args.items() if k != "page" and v}
    return render_template("dashboard.html", pagination=pagination, tab=tab, qargs=qargs,
                           f=request.args)


# ----------------------------------------------------------------- items
def handle_item_form(item_type, item=None):
    tpl = "report_lost.html" if item_type == "Lost" else "report_found.html"
    values = {}
    if item:
        values = {"item_name": item.item_name, "category": item.category,
                  "description": item.description, "report_date": item.report_date.isoformat(),
                  "location": item.location, "additional_info": item.additional_info or "",
                  "contact_preference": item.contact_preference}
    if request.method == "POST":
        f = request.form
        values = {k: f.get(k, "").strip() for k in
                  ("item_name", "category", "description", "report_date", "location",
                   "additional_info", "contact_preference")}
        errors = []
        d = parse_date(values["report_date"])
        valid_cats = {c.name for c in Category.query.all()}
        if not 2 <= len(values["item_name"]) <= 100:
            errors.append("Item name must be 2-100 characters.")
        if values["category"] not in valid_cats:
            errors.append("Choose a valid category.")
        if not 10 <= len(values["description"]) <= 2000:
            errors.append("Description must be 10-2000 characters.")
        if not 2 <= len(values["location"]) <= 150:
            errors.append("Location must be 2-150 characters.")
        if d is None or d > date.today():
            errors.append("Enter a valid date that is not in the future.")
        if len(values["additional_info"]) > 1000:
            errors.append("Additional information is too long (max 1000).")
        if values["contact_preference"] not in CONTACT_PREFS:
            values["contact_preference"] = "messages"
        new_image = None
        file = request.files.get("image")
        if file and file.filename:
            try:
                new_image = save_image(file)
            except ValueError as e:
                errors.append(str(e))
        if errors:
            delete_image(new_image)
            for e in errors:
                flash(e, "danger")
        else:
            if item is None:
                item = Item(user_id=current_user.id, item_type=item_type)
                db.session.add(item)
            item.item_name, item.category = values["item_name"], values["category"]
            item.description, item.location = values["description"], values["location"]
            item.report_date, item.additional_info = d, values["additional_info"] or None
            item.contact_preference = values["contact_preference"]
            if new_image:
                delete_image(item.image)
                item.image = new_image
            db.session.commit()
            flash("Report saved.", "success")
            return redirect(url_for("item_details", item_id=item.id))
    return render_template(tpl, v=values, item=item, item_type=item_type,
                           action=request.path)


@app.route("/report/lost", methods=["GET", "POST"])
@login_required
def report_lost():
    return handle_item_form("Lost")


@app.route("/report/found", methods=["GET", "POST"])
@login_required
def report_found():
    return handle_item_form("Found")


@app.route("/item/<int:item_id>")
def item_details(item_id):
    item = db.get_or_404(Item, item_id)
    authed = current_user.is_authenticated
    is_owner = authed and current_user.id == item.user_id
    private = authed and (is_owner or current_user.is_admin)
    matches, claims, my_claim, approved_contact = [], [], None, None
    if is_owner and item.status == "Open":
        cands = (Item.query.filter(Item.item_type != item.item_type, Item.status == "Open")
                 .order_by(Item.created_at.desc()).limit(300).all())
        matches = find_matches(item, cands)
    if private:
        claims = item.claims
    elif authed:
        my_claim = (Claim.query.filter_by(item_id=item.id, claimant_id=current_user.id)
                    .order_by(Claim.created_at.desc()).first())
        if my_claim and my_claim.status == "Approved":
            pref = item.contact_preference
            if pref == "phone" and item.owner.phone:
                approved_contact = f"Phone: {item.owner.phone}"
            elif pref == "email":
                approved_contact = f"Email: {item.owner.email}"
    return render_template("item_details.html", item=item, is_owner=is_owner, private=private,
                           matches=matches, claims=claims, my_claim=my_claim,
                           approved_contact=approved_contact)


@app.route("/item/<int:item_id>/edit", methods=["GET", "POST"])
@login_required
def edit_item(item_id):
    item = db.get_or_404(Item, item_id)
    if current_user.id != item.user_id:
        abort(403)
    return handle_item_form(item.item_type, item)


@app.route("/item/<int:item_id>/delete", methods=["POST"])
@login_required
def delete_item(item_id):
    item = db.get_or_404(Item, item_id)
    if not can_manage(item):
        abort(403)
    delete_image(item.image)
    db.session.delete(item)
    db.session.commit()
    flash("Listing removed.", "success")
    nxt = request.form.get("next")
    return redirect(nxt if nxt and is_safe_url(nxt) else url_for("dashboard"))


@app.route("/item/<int:item_id>/flag", methods=["POST"])
@login_required
def flag_item(item_id):
    item = db.get_or_404(Item, item_id)
    if item.user_id != current_user.id:
        item.flagged = True
        db.session.commit()
        flash("Thanks. An administrator will review this listing.", "info")
    return redirect(url_for("item_details", item_id=item.id))


# ----------------------------------------------------------------- claims
@app.route("/item/<int:item_id>/claim", methods=["POST"])
@login_required
def submit_claim(item_id):
    item = db.get_or_404(Item, item_id)
    if item.user_id == current_user.id:
        flash("You cannot claim your own report.", "danger")
    elif item.status != "Open":
        flash("This item has already been returned.", "danger")
    elif Claim.query.filter_by(item_id=item.id, claimant_id=current_user.id,
                               status="Pending").first():
        flash("You already have a pending claim for this item.", "warning")
    else:
        details = request.form.get("claim_details", "").strip()
        if not 20 <= len(details) <= 2000:
            flash("Please give 20-2000 characters of identifying details.", "danger")
        else:
            db.session.add(Claim(item_id=item.id, claimant_id=current_user.id,
                                 claim_details=details))
            db.session.commit()
            flash("Claim submitted. The reporter will review it.", "success")
    return redirect(url_for("item_details", item_id=item.id))


@app.route("/claim/<int:claim_id>/<action>", methods=["POST"])
@login_required
def review_claim(claim_id, action):
    claim = db.get_or_404(Claim, claim_id)
    item = claim.item
    if item.user_id != current_user.id:
        abort(403)
    if action not in ("approve", "reject") or claim.status != "Pending":
        abort(400)
    if action == "approve":
        claim.status = "Approved"
        item.status = "Returned"
        for other in item.claims:
            if other.id != claim.id and other.status == "Pending":
                other.status = "Rejected"
        flash("Claim approved. The item is marked as returned.", "success")
    else:
        claim.status = "Rejected"
        flash("Claim rejected.", "info")
    db.session.commit()
    return redirect(url_for("item_details", item_id=item.id))


# ----------------------------------------------------------------- messages
@app.route("/messages")
@login_required
def messages():
    uid = current_user.id
    msgs = (Message.query.filter(or_(Message.sender_id == uid, Message.receiver_id == uid))
            .order_by(Message.created_at.desc()).all())
    threads = {}
    for m in msgs:
        other = m.receiver if m.sender_id == uid else m.sender
        t = threads.setdefault((m.item_id, other.id),
                               {"item": m.item, "other": other, "last": m, "unread": 0})
        if m.receiver_id == uid and not m.is_read:
            t["unread"] += 1
    active, convo = None, []
    item_id, other_id = request.args.get("item", type=int), request.args.get("user", type=int)
    if item_id and other_id:
        item, other = db.session.get(Item, item_id), db.session.get(User, other_id)
        if not item or not other or not can_message(item, other_id):
            abort(404)
        active = {"item": item, "other": other}
        convo = (Message.query.filter_by(item_id=item_id)
                 .filter(or_((Message.sender_id == uid) & (Message.receiver_id == other_id),
                             (Message.sender_id == other_id) & (Message.receiver_id == uid)))
                 .order_by(Message.created_at.asc()).all())
        for m in convo:
            if m.receiver_id == uid and not m.is_read:
                m.is_read = True
        db.session.commit()
    return render_template("messages.html", threads=list(threads.values()),
                           active=active, convo=convo)


@app.route("/messages/send", methods=["POST"])
@login_required
def send_message():
    item = db.get_or_404(Item, request.form.get("item_id", type=int) or 0)
    receiver_id = request.form.get("receiver_id", type=int) or 0
    text = request.form.get("message", "").strip()
    if not can_message(item, receiver_id):
        abort(403)
    if not 1 <= len(text) <= 1000:
        flash("Message must be 1-1000 characters.", "danger")
    else:
        db.session.add(Message(sender_id=current_user.id, receiver_id=receiver_id,
                               item_id=item.id, message=text))
        db.session.commit()
        flash("Message sent.", "success")
    return redirect(url_for("messages", item=item.id, user=receiver_id))


# ----------------------------------------------------------------- admin
@app.route("/admin")
@admin_required
def admin():
    stats = {
        "users": User.query.count(),
        "lost": Item.query.filter_by(item_type="Lost").count(),
        "found": Item.query.filter_by(item_type="Found").count(),
        "returned": Item.query.filter_by(status="Returned").count(),
        "flagged": Item.query.filter_by(flagged=True).count(),
    }
    return render_template(
        "admin.html", stats=stats,
        users=User.query.order_by(User.created_at.desc()).limit(200).all(),
        flagged=Item.query.filter_by(flagged=True).order_by(Item.created_at.desc()).all(),
        items=Item.query.order_by(Item.created_at.desc()).limit(100).all(),
        cats=Category.query.order_by(Category.name).all())


@app.route("/admin/user/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id:
        flash("You cannot deactivate yourself.", "danger")
    else:
        user.active = not user.active
        db.session.commit()
        flash(f"User {'activated' if user.active else 'deactivated'}.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user.id or user.is_admin:
        flash("Admin accounts cannot be deleted here.", "danger")
        return redirect(url_for("admin"))
    for it in user.items:
        delete_image(it.image)
    Message.query.filter(or_(Message.sender_id == user.id,
                             Message.receiver_id == user.id)).delete(synchronize_session=False)
    Claim.query.filter_by(claimant_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/item/<int:item_id>/unflag", methods=["POST"])
@admin_required
def admin_unflag(item_id):
    item = db.get_or_404(Item, item_id)
    item.flagged = False
    db.session.commit()
    flash("Flag cleared.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/category/add", methods=["POST"])
@admin_required
def admin_add_category():
    name = request.form.get("name", "").strip()
    if not 2 <= len(name) <= 50:
        flash("Category name must be 2-50 characters.", "danger")
    elif Category.query.filter(func.lower(Category.name) == name.lower()).first():
        flash("That category already exists.", "warning")
    else:
        db.session.add(Category(name=name))
        db.session.commit()
        flash("Category added.", "success")
    return redirect(url_for("admin"))


@app.route("/admin/category/<int:cat_id>/delete", methods=["POST"])
@admin_required
def admin_delete_category(cat_id):
    cat = db.get_or_404(Category, cat_id)
    if Item.query.filter_by(category=cat.name).count():
        flash("Category is in use and cannot be deleted.", "danger")
    else:
        db.session.delete(cat)
        db.session.commit()
        flash("Category deleted.", "success")
    return redirect(url_for("admin"))


# ----------------------------------------------------------------- errors
MESSAGES = {400: "Bad request or expired form. Please go back and try again.",
            403: "You do not have permission to do that.",
            404: "We could not find that page.",
            413: "That file is too large (max 5 MB).",
            500: "Something went wrong on our side."}


def _error(code):
    def handler(e):
        return render_template("error.html", code=code, message=MESSAGES[code]), code
    return handler


for _code in MESSAGES:
    app.register_error_handler(_code, _error(_code))


# ----------------------------------------------------------------- seed + run
def seed():
    db.create_all()
    if Category.query.count() == 0:
        db.session.add_all(Category(name=n) for n in app.config["DEFAULT_CATEGORIES"])
    if not User.query.filter_by(is_admin=True).first():
        pw = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(10)
        admin_user = User(username="admin", email="admin@lostfound.local", is_admin=True)
        admin_user.set_password(pw)
        db.session.add(admin_user)
        print(f"\n*** Admin created -> email: admin@lostfound.local  password: {pw}\n")
    db.session.commit()


with app.app_context():
    seed()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
