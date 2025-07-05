import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import base64
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# Database initialization
def init_db():
    with sqlite3.connect('recipes.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
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
            c.execute("INSERT INTO users (id, username, password, role, points) VALUES (?, ?, ?, ?, ?)",
                      (admin_id, 'admin', generate_password_hash('admin123'), 'admin', 0))
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
        conn = get_db()
        try:
            user_id = str(uuid.uuid4())
            conn.execute("INSERT INTO users (id, username, password, role, points) VALUES (?, ?, ?, ?, ?)",
                         (user_id, username, generate_password_hash(password), 'user', 0))
            conn.commit()
            flash('Registration successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists')
    return render_template('register.html')

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
        # Posting logic...
        pass

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
    if request.method == 'POST':
        title = request.form['title']
        ingredients = request.form['ingredients']
        instructions = request.form['instructions']
        conn.execute("UPDATE recipes SET title = ?, ingredients = ?, instructions = ? WHERE id = ?",
                     (title, ingredients, instructions, recipe_id))
        conn.commit()
        flash('Recipe updated successfully')
        return redirect(url_for('index'))
    return render_template('edit_recipe.html', recipe=recipe)

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