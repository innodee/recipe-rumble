import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_dance.contrib.facebook import make_facebook_blueprint, facebook
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized, oauth_error
from flask_dance.consumer.storage.sqla import SQLAlchemyStorage # Or other storage
from sqlalchemy.orm.exc import NoResultFound
import os
import uuid
import base64
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'supersecretkey123' # Keep this, Flask-Dance needs it

# OAuth 2.0 client IDs and secrets - REPLACE WITH YOUR ACTUAL CREDENTIALS
# For development, you can often use http://localhost:5000 as the redirect URI
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1' # Allow HTTP for local development
app.config["FACEBOOK_OAUTH_CLIENT_ID"] = "YOUR_FACEBOOK_APP_ID"
app.config["FACEBOOK_OAUTH_CLIENT_SECRET"] = "YOUR_FACEBOOK_APP_SECRET"
app.config["GOOGLE_OAUTH_CLIENT_ID"] = "YOUR_GOOGLE_CLIENT_ID"
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = "YOUR_GOOGLE_CLIENT_SECRET"

facebook_bp = make_facebook_blueprint(
    client_id=app.config["FACEBOOK_OAUTH_CLIENT_ID"],
    client_secret=app.config["FACEBOOK_OAUTH_CLIENT_SECRET"],
    scope=["email"], # Request email permission
    redirect_to="facebook_login" # Route to handle after Facebook auth
)
app.register_blueprint(facebook_bp, url_prefix="/login")

google_bp = make_google_blueprint(
    client_id=app.config["GOOGLE_OAUTH_CLIENT_ID"],
    client_secret=app.config["GOOGLE_OAUTH_CLIENT_SECRET"],
    scope=["openid", "https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"], # Standard scopes
    redirect_to="google_login" # Route to handle after Google auth
)
app.register_blueprint(google_bp, url_prefix="/login")


# Database initialization
def init_db():
    with sqlite3.connect('recipes.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT UNIQUE NOT NULL,
            social_provider TEXT,
            social_id TEXT,
            role TEXT,
            points INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS recipes (
            id TEXT PRIMARY KEY,
            title TEXT,
            ingredients TEXT,
            instructions TEXT,
            created_by TEXT,
            image BLOB,
            posted_at TEXT,
            is_active INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS submissions (
            submission_id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipe_id TEXT,
            user_id TEXT,
            image BLOB,
            submitted_at TEXT
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS votes (
            user_id TEXT,
            submission_id INTEGER,
            recipe_id TEXT,
            PRIMARY KEY (user_id, submission_id)
        )''')
        # Create default admin if not exists
        c.execute("SELECT * FROM users WHERE role='admin'")
        if not c.fetchone():
            admin_id = str(uuid.uuid4())
            # Add a placeholder email for the admin user
            c.execute("INSERT INTO users (id, username, password, email, role, points) VALUES (?, ?, ?, ?, ?, ?)",
                      (admin_id, 'admin', generate_password_hash('admin123'), 'admin@example.com', 'admin', 0))
        conn.commit()

# Database connection helper
def get_db():
    conn = sqlite3.connect('recipes.db')
    conn.row_factory = sqlite3.Row
    return conn

# Helper to check recipe status and calculate time left
def get_recipe_status(posted_at):
    if not posted_at:
        return 'inactive', 0
    try:
        posted_time = datetime.fromisoformat(posted_at)
    except (ValueError, TypeError):
        return 'inactive', 0
    submission_end = posted_time + timedelta(days=4)
    voting_end = submission_end + timedelta(days=3)
    now = datetime.utcnow()
    if now < submission_end:
        time_left = (submission_end - now).total_seconds() * 1000  # Milliseconds
        return 'submission', time_left
    elif now < voting_end:
        time_left = (voting_end - now).total_seconds() * 1000
        return 'voting', time_left
    return 'inactive', 0

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn = get_db()
    recipe = conn.execute("SELECT * FROM recipes WHERE is_active = 1").fetchone()
    
    if recipe:
        status, time_left = get_recipe_status(recipe['posted_at'])
        if status == 'inactive':
            conn.execute("UPDATE recipes SET is_active = 0 WHERE id = ?", (recipe['id'],))
            conn.commit()
            recipe = None
        else:
            print(f"Rendering index with recipe_id={recipe['id']}, posted_at={recipe['posted_at']}, status={status}, time_left={time_left}")
    
    if recipe:
        recipe_dict = dict(recipe)
        if recipe['image']:
            recipe_dict['image_base64'] = base64.b64encode(recipe['image']).decode('utf-8')
        else:
            recipe_dict['image_base64'] = None
        user_submitted = conn.execute("SELECT 1 FROM submissions WHERE user_id = ? AND recipe_id = ?",
                                    (session['user_id'], recipe['id'])).fetchone() is not None
        return render_template('index.html', user=user, recipe=recipe_dict, user_submitted=user_submitted, status=status, time_left=time_left)
    
    return render_template('index.html', user=user, recipe=None, user_submitted=False, status='inactive', time_left=0)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['role'] = user['role']
            if user['role'] == 'admin':
                return redirect(url_for('admin'))
            return redirect(url_for('index'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']  # Get email from form

        if not email: # Or add more robust email validation
            flash('Email is required.')
            return render_template('register.html')

        conn = get_db()
        try:
            user_id = str(uuid.uuid4())
            # Include email in the insert statement, leave social_provider and social_id as NULL for now
            conn.execute("INSERT INTO users (id, username, password, email, role, points) VALUES (?, ?, ?, ?, ?, ?)",
                         (user_id, username, generate_password_hash(password), email, 'user', 0))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed: users.username" in str(e):
                flash('Username already exists.')
            elif "UNIQUE constraint failed: users.email" in str(e):
                flash('Email address already registered.')
            else:
                flash('An error occurred during registration. Please try again.')
    return render_template('register.html')

# Facebook login route - this is where Facebook redirects after auth
@app.route("/facebook_login")
def facebook_login():
    if not facebook.authorized:
        flash("Facebook authorization failed.", "error")
        return redirect(url_for("register")) # Or login page

    resp = facebook.get("/me?fields=id,email,first_name,last_name")
    if not resp.ok:
        flash("Failed to fetch user info from Facebook.", "error")
        return redirect(url_for("register"))

    fb_user = resp.json()
    user_email = fb_user.get("email")
    user_social_id = fb_user.get("id")
    user_first_name = fb_user.get("first_name", "")
    user_last_name = fb_user.get("last_name", "")

    if not user_email:
        flash("Email not provided by Facebook. Please register manually or ensure your Facebook email is public.", "error")
        return redirect(url_for("register"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (user_email,)).fetchone()

    if user: # User exists with this email
        # Optionally, link account if social_id is not set, or just log them in
        if not user['social_id'] or user['social_provider'] != 'facebook':
            conn.execute("UPDATE users SET social_provider = ?, social_id = ? WHERE id = ?",
                         ('facebook', user_social_id, user['id']))
            conn.commit()
        session['user_id'] = user['id']
        session['role'] = user['role']
        flash('Logged in successfully via Facebook!', 'success')
        return redirect(url_for('index'))
    else: # New user
        username = f"{user_first_name}{user_last_name}".replace(" ", "") or f"fb_{user_social_id}"
        # Ensure username is unique
        temp_username = username
        counter = 1
        while conn.execute("SELECT * FROM users WHERE username = ?", (temp_username,)).fetchone():
            temp_username = f"{username}{counter}"
            counter += 1
        username = temp_username

        user_id = str(uuid.uuid4())
        conn.execute("INSERT INTO users (id, username, email, social_provider, social_id, role, points) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (user_id, username, user_email, 'facebook', user_social_id, 'user', 0))
        conn.commit()
        session['user_id'] = user_id
        session['role'] = 'user'
        flash('Registered and logged in successfully via Facebook!', 'success')
        return redirect(url_for('index'))

# Google login route - this is where Google redirects after auth
@app.route("/google_login")
def google_login():
    if not google.authorized:
        flash("Google authorization failed.", "error")
        return redirect(url_for("register"))

    resp = google.get("/oauth2/v2/userinfo") # Standard endpoint for user info
    if not resp.ok:
        flash("Failed to fetch user info from Google.", "error")
        return redirect(url_for("register"))

    google_user = resp.json()
    user_email = google_user.get("email")
    user_social_id = google_user.get("id")
    user_first_name = google_user.get("given_name", "")
    user_last_name = google_user.get("family_name", "")

    if not user_email:
        flash("Email not provided by Google. Please register manually or ensure your Google email is public.", "error")
        return redirect(url_for("register"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (user_email,)).fetchone()

    if user: # User exists
        if not user['social_id'] or user['social_provider'] != 'google':
            conn.execute("UPDATE users SET social_provider = ?, social_id = ? WHERE id = ?",
                         ('google', user_social_id, user['id']))
            conn.commit()
        session['user_id'] = user['id']
        session['role'] = user['role']
        flash('Logged in successfully via Google!', 'success')
        return redirect(url_for('index'))
    else: # New user
        username = f"{user_first_name}{user_last_name}".replace(" ", "") or f"gl_{user_social_id}"
        # Ensure username is unique
        temp_username = username
        counter = 1
        while conn.execute("SELECT * FROM users WHERE username = ?", (temp_username,)).fetchone():
            temp_username = f"{username}{counter}"
            counter += 1
        username = temp_username

        user_id = str(uuid.uuid4())
        conn.execute("INSERT INTO users (id, username, email, social_provider, social_id, role, points) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (user_id, username, user_email, 'google', user_social_id, 'user', 0))
        conn.commit()
        session['user_id'] = user_id
        session['role'] = 'user'
        flash('Registered and logged in successfully via Google!', 'success')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Admin access required')
        return redirect(url_for('index'))

    active_tab = request.args.get('tab', 'post_recipe')
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()  # Fetch the user info
    active_recipe = conn.execute("SELECT * FROM recipes WHERE is_active = 1").fetchone()

    # Check if the active recipe is inactive
    if active_recipe and get_recipe_status(active_recipe['posted_at'])[0] == 'inactive':
        conn.execute("UPDATE recipes SET is_active = 0 WHERE id = ?", (active_recipe['id'],))
        conn.commit()
        active_recipe = None

    # Handle posting a new recipe
    if active_tab == 'post_recipe' and request.method == 'POST' and not active_recipe:
        title = request.form.get('title')
        ingredients = request.form.get('ingredients')
        instructions = request.form.get('instructions')
        image_file = request.files.get('image')

        if not title or not ingredients or not instructions:
            flash('Title, ingredients, and instructions are required.', 'danger')
        else:
            image_data = None
            if image_file and image_file.filename:
                if not image_file.mimetype.startswith('image/'):
                    flash('Invalid image format. Please upload a PNG or JPEG.', 'danger')
                    return redirect(url_for('admin', tab='post_recipe'))
                image_data = image_file.read()

            try:
                # Deactivate any currently active recipes
                conn.execute("UPDATE recipes SET is_active = 0 WHERE is_active = 1")

                recipe_id = str(uuid.uuid4())
                posted_at = datetime.utcnow().isoformat()
                
                conn.execute("""
                    INSERT INTO recipes (id, title, ingredients, instructions, created_by, image, posted_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (recipe_id, title, ingredients, instructions, session['user_id'], image_data, posted_at, 1))
                conn.commit()
                flash('Recipe posted successfully!', 'success')
                # Refresh active_recipe after posting
                active_recipe = conn.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
                return redirect(url_for('admin', tab='post_recipe')) 
            except sqlite3.Error as e:
                flash(f'Database error: {e}', 'danger')
            except Exception as e:
                flash(f'An unexpected error occurred: {e}', 'danger')
        # Fallthrough here means validation failed or an error occurred,
        # so we re-render the admin page, preserving the active_tab.
        # The active_recipe variable might need to be re-fetched if a new recipe was just posted
        # or if an error occurred mid-process.
        # However, redirecting is cleaner for POST-Redirect-Get pattern.
        # If flash was shown, it will be displayed after redirect.

    submissions = conn.execute('''  -- Fetch all submissions
        SELECT s.submission_id, s.recipe_id, s.submitted_at, u.username, r.title, s.image
        FROM submissions s
        JOIN users u ON s.user_id = u.id
        JOIN recipes r ON s.recipe_id = r.id
    ''').fetchall()

    # Prepare submissions with images
    submissions_with_images = []
    for sub in submissions:
        sub_dict = dict(sub)
        if sub['image']:
            sub_dict['image_base64'] = base64.b64encode(sub['image']).decode('utf-8')
        else:
            sub_dict['image_base64'] = None
        submissions_with_images.append(sub_dict)
    
    users = conn.execute("SELECT username, role, points FROM users").fetchall()

    # Render the template with the user information
    return render_template('admin.html', active_tab=active_tab, submissions=submissions_with_images,
                           users=users, active_recipe=active_recipe, user=user)  # Pass user here

@app.route('/submit_image/<recipe_id>', methods=['POST'])
def submit_image(recipe_id):
    if 'user_id' not in session:
        flash('Please log in')
        return redirect(url_for('login'))
    conn = get_db()
    recipe = conn.execute("SELECT * FROM recipes WHERE id = ? AND is_active = 1", (recipe_id,)).fetchone()
    if not recipe or get_recipe_status(recipe['posted_at'])[0] != 'submission':
        flash('Submissions are not allowed at this time')
        return redirect(url_for('index'))
    existing = conn.execute("SELECT * FROM submissions WHERE user_id = ? AND recipe_id = ?",
                           (session['user_id'], recipe_id)).fetchone()
    if existing:
        flash('You have already submitted an image for this recipe')
        return redirect(url_for('index'))
    if 'image' not in request.files or not request.files['image'].filename:
        flash('No image uploaded')
        return redirect(url_for('index'))
    image_file = request.files['image']
    if not image_file.mimetype.startswith('image/'):
        flash('Invalid image format. Please upload a PNG or JPEG.')
        return redirect(url_for('index'))
    image = image_file.read()
    submitted_at = datetime.utcnow().isoformat()
    conn.execute("INSERT INTO submissions (recipe_id, user_id, image, submitted_at) VALUES (?, ?, ?, ?)",
                 (recipe_id, session['user_id'], image, submitted_at))
    conn.commit()
    flash('Image submitted successfully')
    return redirect(url_for('index'))

@app.route('/vote/<submission_id>')
def vote(submission_id):
    if 'user_id' not in session:
        flash('Please log in')
        return redirect(url_for('login'))
    conn = get_db()
    submission = conn.execute("SELECT * FROM submissions WHERE submission_id = ?", (submission_id,)).fetchone()
    if not submission:
        flash('Invalid submission')
        return redirect(url_for('submissions'))
    recipe = conn.execute("SELECT * FROM recipes WHERE id = ? AND is_active = 1", (submission['recipe_id'],)).fetchone()
    if not recipe or get_recipe_status(recipe['posted_at'])[0] != 'voting':
        flash('Voting is not allowed at this time')
        return redirect(url_for('submissions'))
    existing = conn.execute("SELECT * FROM votes WHERE user_id = ? AND recipe_id = ?",
                           (session['user_id'], recipe['id'])).fetchone()
    if existing:
        flash('You have already voted for this recipe')
        return redirect(url_for('submissions'))
    if session['role'] != 'admin':
        conn.execute("INSERT INTO votes (user_id, submission_id, recipe_id) VALUES (?, ?, ?)",
                     (session['user_id'], submission_id, recipe['id']))
        conn.execute("UPDATE users SET points = points + 1 WHERE id = (SELECT user_id FROM submissions WHERE submission_id = ?)",
                     (submission_id,))
        conn.commit()
        flash('Vote recorded successfully')
    else:
        flash('Admins cannot vote')
    return redirect(url_for('submissions'))

@app.route('/submissions')
def submissions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    conn = get_db()
    recipe = conn.execute("SELECT * FROM recipes WHERE is_active = 1").fetchone()
    
    if recipe:
        status, time_left = get_recipe_status(recipe['posted_at'])
        if status == 'inactive':
            conn.execute("UPDATE recipes SET is_active = 0 WHERE id = ?", (recipe['id'],))
            conn.commit()
            recipe = None
        else:
            print(f"Rendering submissions with recipe_id={recipe['id']}, posted_at={recipe['posted_at']}, status={status}, time_left={time_left}")
    
    submissions_with_images = []
    if recipe:
        submissions = conn.execute("SELECT submission_id, image FROM submissions WHERE recipe_id = ?", (recipe['id'],)).fetchall()
        for sub in submissions:
            sub_dict = dict(sub)
            if sub['image']:
                sub_dict['image_base64'] = base64.b64encode(sub['image']).decode('utf-8')
            else:
                sub_dict['image_base64'] = None
            submissions_with_images.append(sub_dict)
        user_voted = conn.execute("SELECT 1 FROM votes WHERE user_id = ? AND recipe_id = ?",
                                 (session['user_id'], recipe['id'])).fetchone() is not None
        return render_template('submissions.html', user=user, recipe=recipe, submissions=submissions_with_images,
                             user_voted=user_voted, status=status, time_left=time_left)
    
    return render_template('submissions.html', user=user, recipe=None, submissions=[], user_voted=False, status='inactive', time_left=0)

@app.route('/edit_recipe/<recipe_id>', methods=['GET', 'POST'])
def edit_recipe(recipe_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Admin access required')
        return redirect(url_for('index'))
    conn = get_db()
    recipe = conn.execute("SELECT * FROM recipes WHERE id = ?", (recipe_id,)).fetchone()
    if not recipe:
        flash('Recipe not found')
        return redirect(url_for('index'))
    # Fetch the user information
    user = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    if request.method == 'POST':
        title = request.form['title']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        conn.execute("UPDATE recipes SET title = ?, ingredients = ?, instructions = ? WHERE id = ?",
                     (title, ingredients, instructions, recipe_id))
        conn.commit()
        flash('Recipe updated successfully')
        return redirect(url_for('index'))
    return render_template('edit_recipe.html', recipe=recipe, user=user)  # Pass user to template

@app.route('/delete_recipe/<recipe_id>')
def delete_recipe(recipe_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Admin access required')
        return redirect(url_for('index'))
    conn = get_db()
    conn.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    conn.execute("DELETE FROM submissions WHERE recipe_id = ?", (recipe_id,))
    conn.execute("DELETE FROM votes WHERE recipe_id = ?", (recipe_id,))
    conn.commit()
    flash('Recipe deleted successfully')
    return redirect(url_for('index'))

@app.route('/leaderboard')
def leaderboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = get_db().execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    users = get_db().execute("SELECT username, points FROM users WHERE role = 'user' ORDER BY points DESC").fetchall()
    return render_template('leaderboard.html', users=users, user=user)  # Pass the user object

# Initialize database and run app
if __name__ == '__main__':
    init_db()
    app.run(debug=True)