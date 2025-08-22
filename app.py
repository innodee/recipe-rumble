import os
import base64
import io
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ------------------------------------------------------------------------------
# Flask setup
# ------------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "recipe_rumble.db"

# Submission/voting windows (tweak as needed)
SUBMISSION_HOURS = int(os.environ.get("RR_SUBMISSION_HOURS", "48"))
VOTING_HOURS = int(os.environ.get("RR_VOTING_HOURS", "24"))

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
MAX_FILE_BYTES = 5 * 1024 * 1024  # 5MB limit

# ------------------------------------------------------------------------------
# Optional OAuth (Option B): SessionStorage only, no SQLAlchemy required
# We register real blueprints if Flask-Dance is installed; else, stub routes
# ------------------------------------------------------------------------------
try:
    from flask_dance.contrib.google import make_google_blueprint
    from flask_dance.contrib.facebook import make_facebook_blueprint
    from flask_dance.consumer.storage import SessionStorage

    google_bp = make_google_blueprint(
        client_id=os.environ.get("GOOGLE_OAUTH_CLIENT_ID", "missing"),
        client_secret=os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET", "missing"),
        scope=["profile", "email"],
        redirect_to="index",
        storage=SessionStorage(),
    )
    app.register_blueprint(google_bp, url_prefix="/login")

    facebook_bp = make_facebook_blueprint(
        client_id=os.environ.get("FACEBOOK_OAUTH_CLIENT_ID", "missing"),
        client_secret=os.environ.get("FACEBOOK_OAUTH_CLIENT_SECRET", "missing"),
        scope=["public_profile", "email"],
        redirect_to="index",
        storage=SessionStorage(),
    )
    app.register_blueprint(facebook_bp, url_prefix="/login")
except Exception:
    # Fallback "dummy" blueprints so url_for('google.login') and ('facebook.login') resolve
    from flask import Blueprint

    google_dummy = Blueprint("google", __name__, url_prefix="/login/google")
    facebook_dummy = Blueprint("facebook", __name__, url_prefix="/login/facebook")

    @google_dummy.route("/login")
    def login():  # endpoint: google.login
        flash("Google OAuth is not configured on this deployment.", "warning")
        return redirect(url_for("login"))

    @facebook_dummy.route("/login")
    def login_fb():  # endpoint: facebook.login
        flash("Facebook OAuth is not configured on this deployment.", "warning")
        return redirect(url_for("login"))

    # Ensure endpoints exist as 'google.login' and 'facebook.login'
    google_dummy.add_url_rule("", endpoint="login", view_func=google_dummy.view_functions["login"])
    facebook_dummy.add_url_rule("", endpoint="login", view_func=facebook_dummy.view_functions["login_fb"])

    app.register_blueprint(google_dummy, url_prefix="/login/google")
    app.register_blueprint(facebook_dummy, url_prefix="/login/facebook")

# ------------------------------------------------------------------------------
# DB helpers (sqlite3)
# ------------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            points INTEGER NOT NULL DEFAULT 0,
            email TEXT,
            phone_number TEXT
        );
        CREATE TABLE IF NOT EXISTS recipes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            ingredients TEXT NOT NULL,
            instructions TEXT NOT NULL,
            image_base64 BLOB,
            posted_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            image_base64 BLOB,
            submitted_at INTEGER NOT NULL,
            FOREIGN KEY(recipe_id) REFERENCES recipes(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            submission_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            voted_at INTEGER NOT NULL,
            UNIQUE(submission_id, user_id),
            FOREIGN KEY(submission_id) REFERENCES submissions(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()

@app.before_first_request
def bootstrap():
    init_db()
    # Create default admin if none exists
    db = get_db()
    cur = db.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        db.execute(
            "INSERT INTO users (username, password_hash, role, points) VALUES (?, ?, 'admin', 0)",
            ("admin", generate_password_hash("admin")),
        )
        db.commit()

# ------------------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------------------
def utcnow_ts() -> int:
    return int(datetime.now(timezone.utc).timestamp())

def allowed_file(filename: str) -> bool:
    if not filename or "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def file_to_jpeg_base64(storage_file) -> str | None:
    """
    Read a Werkzeug FileStorage and return a JPEG base64 string.
    If Pillow is available, convert to JPEG; else, just base64 the raw bytes.
    """
    if storage_file is None or storage_file.filename == "":
        return None
    filename = secure_filename(storage_file.filename)
    if not allowed_file(filename):
        return None
    data = storage_file.read()
    if not data:
        return None
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("File too large (max 5MB)")
    # Attempt conversion to JPEG via Pillow for consistency
    try:
        from PIL import Image
        img = Image.open(io.BytesIO(data)).convert("RGB")
        out = io.BytesIO()
        img.save(out, format="JPEG", quality=85)
        return base64.b64encode(out.getvalue()).decode("ascii")
    except Exception:
        # Fallback: base64 original bytes (will often still render)
        return base64.b64encode(data).decode("ascii")

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return row

def get_active_recipe():
    """Return the most recently posted recipe (simple 'active' rule)."""
    db = get_db()
    row = db.execute(
        "SELECT * FROM recipes ORDER BY posted_at DESC LIMIT 1"
    ).fetchone()
    return row

def compute_status_and_time_left(posted_at_ts: int):
    """Return status ('submission', 'voting', 'inactive') and time_left_ms for the current phase."""
    if not posted_at_ts:
        return "inactive", 0
    start = datetime.fromtimestamp(posted_at_ts, tz=timezone.utc)
    now = datetime.now(timezone.utc)
    submission_end = start + timedelta(hours=SUBMISSION_HOURS)
    voting_end = submission_end + timedelta(hours=VOTING_HOURS)

    if now < submission_end:
        return "submission", int((submission_end - now).total_seconds() * 1000)
    elif now < voting_end:
        return "voting", int((voting_end - now).total_seconds() * 1000)
    else:
        return "inactive", 0

def user_points(user_id: int) -> int:
    db = get_db()
    # Points = number of votes across user's submissions
    row = db.execute(
        """
        SELECT COUNT(v.id) AS pts
        FROM votes v
        JOIN submissions s ON s.id = v.submission_id
        WHERE s.user_id = ?
        """,
        (user_id,),
    ).fetchone()
    return int(row["pts"] or 0)

@app.context_processor
def inject_now():
    return {"now": datetime.now()}

# ------------------------------------------------------------------------------
# Routes
# ------------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    user_row = current_user()

    # Build user dict for template
    user_dict = {
        "username": user_row["username"] if user_row else "Guest",
        "points": user_points(user_row["id"]) if user_row else 0,
        "role": (user_row["role"] if user_row else "guest"),
    }

    recipe = get_active_recipe()
    if recipe:
        status, time_left = compute_status_and_time_left(recipe["posted_at"])
        # Has the current user submitted?
        user_submitted = False
        if user_row:
            r = db.execute(
                "SELECT 1 FROM submissions WHERE recipe_id=? AND user_id=?",
                (recipe["id"], user_row["id"]),
            ).fetchone()
            user_submitted = r is not None

        recipe_dict = {
            "id": recipe["id"],
            "title": recipe["title"],
            "ingredients": recipe["ingredients"],
            "instructions": recipe["instructions"],
            "image_base64": recipe["image_base64"],  # JPEG base64 preferred
        }
    else:
        status, time_left, user_submitted, recipe_dict = "inactive", 0, False, None

    return render_template(
        "index.html",
        user=user_dict,
        recipe=recipe_dict,
        user_submitted=user_submitted,
        status=status,
        time_left=time_left,
    )

@app.route("/submissions")
def submissions():
    db = get_db()
    user_row = current_user()
    user_dict = {
        "username": user_row["username"] if user_row else "Guest",
        "points": user_points(user_row["id"]) if user_row else 0,
        "role": (user_row["role"] if user_row else "guest"),
    }

    recipe = get_active_recipe()
    if not recipe:
        return render_template(
            "submissions.html",
            user=user_dict,
            recipe=None,
            status="inactive",
            time_left=0,
            submissions=[],
            user_voted=False,
        )

    status, time_left = compute_status_and_time_left(recipe["posted_at"])

    rows = db.execute(
        """
        SELECT s.id AS submission_id, s.image_base64, s.submitted_at,
               u.username, r.title
        FROM submissions s
        JOIN users u ON u.id = s.user_id
        JOIN recipes r ON r.id = s.recipe_id
        WHERE s.recipe_id = ?
        ORDER BY s.submitted_at DESC
        """,
        (recipe["id"],),
    ).fetchall()

    # Has user voted in this recipe (any submission)?
    user_voted = False
    if user_row:
        voted_row = db.execute(
            """
            SELECT 1 FROM votes v
            JOIN submissions s ON s.id = v.submission_id
            WHERE s.recipe_id = ? AND v.user_id = ?
            """,
            (recipe["id"], user_row["id"]),
        ).fetchone()
        user_voted = voted_row is not None

    submission_dicts = []
    for r in rows:
        submission_dicts.append(
            {
                "submission_id": r["submission_id"],
                "image_base64": r["image_base64"],
                "submitted_at": datetime.fromtimestamp(r["submitted_at"]).strftime(
                    "%Y-%m-%d %H:%M"
                ),
                "username": r["username"],
                "title": r["title"],
            }
        )

    return render_template(
        "submissions.html",
        user=user_dict,
        recipe={"id": recipe["id"], "title": recipe["title"]},
        status=status,
        time_left=time_left,
        submissions=submission_dicts,
        user_voted=user_voted,
    )

@app.route("/vote/<int:submission_id>")
def vote(submission_id: int):
    db = get_db()
    user_row = current_user()
    if not user_row or user_row["role"] == "admin":
        flash("You must be a logged-in non-admin user to vote.", "warning")
        return redirect(url_for("submissions"))

    # Check voting window based on active recipe
    recipe = get_active_recipe()
    if not recipe:
        flash("No active recipe to vote on.", "warning")
        return redirect(url_for("submissions"))

    status, _ = compute_status_and_time_left(recipe["posted_at"])
    if status != "voting":
        flash("Voting is not currently open.", "warning")
        return redirect(url_for("submissions"))

    # Ensure submission belongs to active recipe
    srow = db.execute(
        "SELECT * FROM submissions WHERE id = ? AND recipe_id = ?",
        (submission_id, recipe["id"]),
    ).fetchone()
    if not srow:
        flash("Invalid submission.", "danger")
        return redirect(url_for("submissions"))

    # Check not already voted in this recipe
    exists = db.execute(
        """
        SELECT 1 FROM votes v
        JOIN submissions s ON s.id = v.submission_id
        WHERE s.recipe_id = ? AND v.user_id = ?
        """,
        (recipe["id"], user_row["id"]),
    ).fetchone()
    if exists:
        flash("You have already voted for this recipe.", "info")
        return redirect(url_for("submissions"))

    db.execute(
        "INSERT INTO votes (submission_id, user_id, voted_at) VALUES (?, ?, ?)",
        (submission_id, user_row["id"], utcnow_ts()),
    )
    db.commit()
    flash("Vote recorded. Thanks!", "success")
    return redirect(url_for("submissions"))

@app.route("/leaderboard")
def leaderboard():
    db = get_db()
    rows = db.execute(
        """
        SELECT u.id, u.username,
               COALESCE((
                 SELECT COUNT(v.id)
                 FROM votes v
                 JOIN submissions s ON s.id = v.submission_id
                 WHERE s.user_id = u.id
               ), 0) AS points
        FROM users u
        ORDER BY points DESC, username ASC
        """
    ).fetchall()
    users = [{"username": r["username"], "points": int(r["points"])} for r in rows]
    # Provide a user object for header
    user_row = current_user()
    user = {
        "username": user_row["username"] if user_row else "Guest",
        "points": user_points(user_row["id"]) if user_row else 0,
        "role": (user_row["role"] if user_row else "guest"),
    }
    return render_template("leaderboard.html", users=users, user=user)

@app.route("/voting")
def voting():
    # Static page explaining voting; your template links back to submissions
    return render_template("voting.html")

# ------------------------------------------------------------------------------
# Auth
# ------------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            session["user_id"] = row["id"]
            session["role"] = row["role"]
            flash("Welcome back!", "success")
            return redirect(url_for("index"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("password_confirm") or ""
        email = (request.form.get("email") or "").strip()
        phone = (request.form.get("phone_number") or "").strip()

        if not username or not password or password != confirm:
            flash("Please supply a username and matching passwords.", "danger")
            return render_template("register.html")

        db = get_db()
        exists = db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
        if exists:
            flash("Username is already taken.", "warning")
            return render_template("register.html")

        # First non-admin user? Keep admin as seeded; all new users are 'user'
        db.execute(
            "INSERT INTO users (username, password_hash, role, email, phone_number) VALUES (?, ?, 'user', ?, ?)",
            (username, generate_password_hash(password), email, phone),
        )
        db.commit()
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.", "info")
    return redirect(url_for("login"))

# ------------------------------------------------------------------------------
# Submissions
# ------------------------------------------------------------------------------
@app.route("/submit_image/<int:recipe_id>", methods=["POST"])
def submit_image(recipe_id: int):
    user = current_user()
    if not user or user["role"] == "admin":
        flash("Only logged-in non-admin users can submit.", "warning")
        return redirect(url_for("index"))

    db = get_db()
    recipe = db.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("index"))

    status, _ = compute_status_and_time_left(recipe["posted_at"])
    if status != "submission":
        flash("Submission window is closed.", "warning")
        return redirect(url_for("index"))

    # Ensure not already submitted
    exists = db.execute(
        "SELECT 1 FROM submissions WHERE recipe_id = ? AND user_id = ?",
        (recipe_id, user["id"]),
    ).fetchone()
    if exists:
        flash("You already submitted for this recipe.", "info")
        return redirect(url_for("index"))

    f = request.files.get("image")
    try:
        b64 = file_to_jpeg_base64(f)
    except ValueError as e:
        flash(str(e), "danger")
        return redirect(url_for("index"))

    if not b64:
        flash("Please upload a PNG or JPEG image.", "danger")
        return redirect(url_for("index"))

    db.execute(
        "INSERT INTO submissions (recipe_id, user_id, image_base64, submitted_at) VALUES (?, ?, ?, ?)",
        (recipe_id, user["id"], b64, utcnow_ts()),
    )
    db.commit()
    flash("Submission uploaded. Good luck!", "success")
    return redirect(url_for("submissions"))

# ------------------------------------------------------------------------------
# Admin
# ------------------------------------------------------------------------------
def require_admin():
    user = current_user()
    if not user or user["role"] != "admin":
        flash("Admin access required.", "danger")
        return False
    return True

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if not require_admin():
        return redirect(url_for("index"))

    tab = (request.args.get("tab") or "post_recipe").strip()
    db = get_db()

    active_recipe = get_active_recipe()
    users = db.execute("SELECT id, username, role, points FROM users ORDER BY username").fetchall()

    if request.method == "POST" and tab == "post_recipe" and not active_recipe:
        title = (request.form.get("title") or "").strip()
        ingredients = (request.form.get("ingredients") or "").strip()
        instructions = (request.form.get("instructions") or "").strip()
        file = request.files.get("image")

        if not title or not ingredients or not instructions:
            flash("Title, ingredients, and instructions are required.", "danger")
            return render_template(
                "admin.html",
                active_tab=tab,
                active_recipe=active_recipe,
                submissions=[],
                users=users,
            )

        b64 = None
        if file and file.filename:
            b64 = file_to_jpeg_base64(file)
            if not b64:
                flash("Please upload a PNG or JPEG image.", "danger")
                return render_template(
                    "admin.html",
                    active_tab=tab,
                    active_recipe=active_recipe,
                    submissions=[],
                    users=users,
                )

        db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, image_base64, posted_at) VALUES (?, ?, ?, ?, ?)",
            (title, ingredients, instructions, b64, utcnow_ts()),
        )
        db.commit()
        flash("Recipe posted!", "success")
        return redirect(url_for("admin", tab="post_recipe"))

    # View submissions tab
    submissions = []
    if tab == "view_submissions":
        if active_recipe:
            rows = db.execute(
                """
                SELECT s.id AS submission_id, s.image_base64, s.submitted_at,
                       u.username, r.title
                FROM submissions s
                JOIN users u ON u.id = s.user_id
                JOIN recipes r ON r.id = s.recipe_id
                WHERE s.recipe_id = ?
                ORDER BY s.submitted_at DESC
                """,
                (active_recipe["id"],),
            ).fetchall()
            submissions = [
                {
                    "submission_id": r["submission_id"],
                    "image_base64": r["image_base64"],
                    "submitted_at": datetime.fromtimestamp(r["submitted_at"]).strftime(
                        "%Y-%m-%d %H:%M"
                    ),
                    "username": r["username"],
                    "title": r["title"],
                }
                for r in rows
            ]

    return render_template(
        "admin.html",
        active_tab=tab,
        active_recipe=active_recipe,
        submissions=submissions,
        users=users,
    )

@app.route("/edit_recipe/<int:recipe_id>", methods=["GET", "POST"])
def edit_recipe(recipe_id: int):
    if not require_admin():
        return redirect(url_for("index"))
    db = get_db()
    recipe = db.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    if not recipe:
        flash("Recipe not found.", "danger")
        return redirect(url_for("admin"))

    if request.method == "POST":
        title = (request.form.get("title") or "").strip()
        ingredients = (request.form.get("ingredients") or "").strip()
        instructions = (request.form.get("instructions") or "").strip()
        file = request.files.get("image")

        if not title or not ingredients or not instructions:
            flash("Title, ingredients, and instructions are required.", "danger")
            return render_template("edit_recipe.html", recipe=recipe, user=current_user())

        b64 = recipe["image_base64"]
        if file and file.filename:
            b64_new = file_to_jpeg_base64(file)
            if not b64_new:
                flash("Please upload a PNG or JPEG image.", "danger")
                return render_template("edit_recipe.html", recipe=recipe, user=current_user())
            b64 = b64_new

        db.execute(
            "UPDATE recipes SET title=?, ingredients=?, instructions=?, image_base64=? WHERE id=?",
            (title, ingredients, instructions, b64, recipe_id),
        )
        db.commit()
        flash("Recipe updated.", "success")
        return redirect(url_for("admin", tab="post_recipe"))

    return render_template("edit_recipe.html", recipe=recipe, user=current_user())

@app.route("/delete_recipe/<int:recipe_id>")
def delete_recipe(recipe_id: int):
    if not require_admin():
        return redirect(url_for("index"))
    db = get_db()
    # delete dependent rows
    db.execute(
        "DELETE FROM votes WHERE submission_id IN (SELECT id FROM submissions WHERE recipe_id=?)",
        (recipe_id,),
    )
    db.execute("DELETE FROM submissions WHERE recipe_id=?", (recipe_id,))
    db.execute("DELETE FROM recipes WHERE id=?", (recipe_id,))
    db.commit()
    flash("Recipe and related submissions/votes deleted.", "success")
    return redirect(url_for("admin", tab="post_recipe"))

# ------------------------------------------------------------------------------
# WSGI entrypoint
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    # Local dev
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=True)
