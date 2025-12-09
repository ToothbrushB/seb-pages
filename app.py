from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import json
import os
import uuid
import secrets
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
# Path to the exam database JSON file
EXAM_DB_PATH = 'exams.json'
EXAM_APPS_PATH = 'exam_apps.json'
USERS_DB_PATH = 'users.json'

# Load exams from JSON file
def load_exams():
    if os.path.exists(EXAM_DB_PATH):
        with open(EXAM_DB_PATH, 'r') as f:
            return json.load(f)
    return {}

# Load exam apps from JSON file
def load_exam_apps():
    if os.path.exists(EXAM_APPS_PATH):
        with open(EXAM_APPS_PATH, 'r') as f:
            return json.load(f)
    return {}

# Load users from JSON file
def load_users():
    if os.path.exists(USERS_DB_PATH):
        with open(USERS_DB_PATH, 'r') as f:
            return json.load(f)
    return {}

# Save exams to JSON file
def save_exams(exams):
    with open(EXAM_DB_PATH, 'w') as f:
        json.dump(exams, f, indent=2)

# Save users to JSON file
def save_users(users):
    with open(USERS_DB_PATH, 'w') as f:
        json.dump(users, f, indent=2)

# Word list for generating memorable exam keys (expanded for more combinations)
WORD_LIST = [
    'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
    'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
    'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray',
    'yankee', 'zulu', 'azure', 'bronze', 'coral', 'diamond', 'emerald', 'forest',
    'granite', 'harmony', 'ivory', 'jade', 'knight', 'lunar', 'marble', 'nebula',
    'ocean', 'phoenix', 'quartz', 'ruby', 'sapphire', 'tiger', 'unicorn', 'violet',
    'wizard', 'xenon', 'yellow', 'zenith', 'arctic', 'blaze', 'cosmic', 'dragon',
    'eagle', 'flame', 'galaxy', 'hawk', 'inferno', 'jaguar', 'kraken', 'lynx',
    'meteor', 'nova', 'orbit', 'prism', 'quantum', 'raven', 'solar', 'thunder',
    'ultra', 'vortex', 'wolf', 'xeno', 'yeti', 'zodiac', 'atom', 'bolt',
    'cipher', 'drift', 'ember', 'flux', 'glow', 'haze', 'ion', 'jolt',
    'kinetic', 'laser', 'matrix', 'nexus', 'omega', 'pulse', 'quasar', 'radar',
    'spectrum', 'titan', 'unity', 'vertex', 'wave', 'xenith', 'yield', 'zero'
]

def generate_exam_id():
    """Generate a cryptographically secure UUID for exam ID"""
    return str(uuid.uuid4())

def generate_exam_key():
    """Generate a memorable 4-word exam key with cryptographic randomness"""
    # Using secrets module for cryptographically secure random selection
    words = [secrets.choice(WORD_LIST) for _ in range(4)]
    return '-'.join(words).upper()

def exam_id_exists(exam_id):
    """Check if exam ID already exists"""
    return exam_id in EXAMS

def exam_key_exists(exam_key):
    """Check if exam key already exists"""
    return any(exam.get('exam_key') == exam_key for exam in EXAMS.values())

# Initialize exams dictionary
EXAMS = load_exams()
EXAM_APPS = load_exam_apps()
USERS = load_users()

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Admin-only decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('login', next=request.url))
        
        username = session.get('username')
        if username not in USERS or USERS[username].get('role') != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('index'))
        
        return f(*args, **kwargs)
    return decorated_function

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if username in USERS:
            user = USERS[username]
            if check_password_hash(user['password_hash'], password):
                session['username'] = username
                session['user_id'] = user.get('user_id')
                session['name'] = user.get('name', username)
                session['role'] = user.get('role', 'teacher')
                flash(f'Welcome, {user.get("name", username)}!', 'success')
                
                # Redirect to next page if specified, otherwise to index
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('index'))
        
        flash('Invalid username or password', 'error')
        return redirect(url_for('login'))
    
    # If already logged in, redirect to index
    if 'username' in session:
        return redirect(url_for('index'))
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('role', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Home page showing all registered exams"""
    # Admins see all exams, teachers see only their own
    if session.get('role') == 'admin':
        user_exams = EXAMS
    else:
        user_id = session.get('user_id')
        user_exams = {exam_id: exam for exam_id, exam in EXAMS.items() if exam.get('user_id') == user_id}
    
    return render_template('index.html', exams=user_exams)

@app.route('/hash_generator')
def hash_generator():
    return render_template('hash_generator.html')

@app.route('/<exam_id>/exam')
def exam(exam_id):
    """Render the exam launcher page with available apps"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('index'))
    
    exam_data = EXAMS[exam_id]
    
    # Get custom tools for this exam
    tools = exam_data.get('tools', [])
    
    # Prepare SEB data
    seb = {
        'beks': exam_data.get('beks', [exam_data.get('bek', '')]),  # Support both new array and old single value
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256((url_for('exam', exam_id=exam_id, _external=True)+exam_data.get('ua', '')).encode('utf-8')).hexdigest()
    }
    
    return render_template(
        'exam_launcher.html',
        exam_id=exam_id,
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        apps=tools
    )

@app.route('/<exam_id>/app/<app_id>')
def exam_app(exam_id, app_id):
    """Render the exam app page with specific app"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('index'))
    
    exam_data = EXAMS[exam_id]
    
    # Find the tool in the exam's tools list
    tool = None
    for t in exam_data.get('tools', []):
        if t['id'] == app_id:
            tool = t
            break
    
    if not tool:
        flash(f'Tool not found', 'error')
        return redirect(url_for('exam', exam_id=exam_id))
    
    # Prepare SEB data
    seb = {
        'beks': exam_data.get('beks', [exam_data.get('bek', '')]),  # Support both new array and old single value
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256((url_for('exam_app', exam_id=exam_id, app_id=app_id, _external=True)+exam_data.get('ua', '')).encode('utf-8')).hexdigest()
    }
    
    return render_template(
        'exam_app.html',
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        iframe_url=tool['url'],
        app_name=tool['name']
    )

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """Register a new exam"""
    if request.method == 'POST':
        beks = [b.strip() for b in request.form.getlist('bek[]') if b.strip()]
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        
        # Get custom tools
        tool_names = request.form.getlist('tool_name[]')
        tool_urls = request.form.getlist('tool_url[]')
        tool_ids = request.form.getlist('tool_id[]')
        tool_icons = request.form.getlist('tool_icon[]')
        
        # Build tools list
        tools = []
        for i in range(len(tool_names)):
            if tool_names[i] and tool_urls[i]:
                tools.append({
                    'id': tool_ids[i] if i < len(tool_ids) else str(uuid.uuid4()),
                    'name': tool_names[i],
                    'url': tool_urls[i],
                    'icon': tool_icons[i] if i < len(tool_icons) else 'bi-app'
                })
        
        # Validation
        if not tools:
            flash('At least one tool must be added', 'error')
            return redirect(url_for('register'))
        
        # Generate unique exam ID (UUID)
        exam_id = generate_exam_id()
        
        # Generate unique exam key (4 words)
        exam_key = generate_exam_key()
        # Ensure uniqueness (extremely unlikely collision, but check anyway)
        attempts = 0
        while exam_key_exists(exam_key) and attempts < 100:
            exam_key = generate_exam_key()
            attempts += 1
        
        if attempts >= 100:
            flash('Failed to generate unique exam key. Please try again.', 'error')
            return redirect(url_for('register'))
        
        # Create exam entry
        EXAMS[exam_id] = {
            'exam_key': exam_key,
            'custom_name': custom_name,
            'user_id': session.get('user_id'),
            'beks': beks,
            'ck': ck,
            'ua': ua,
            'tools': tools
        }
        
        # Save to file
        save_exams(EXAMS)
        
        flash(f'Exam registered successfully! Exam Key: {exam_key}', 'success')
        # Redirect to a confirmation page showing the exam details
        return redirect(url_for('exam_details', exam_id=exam_id))
    
    return render_template('register.html', exam_apps=EXAM_APPS)

@app.route('/edit/<exam_id>', methods=['GET', 'POST'])
@login_required
def edit_exam(exam_id):
    """Edit an existing exam"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('index'))
    
    # Check ownership (admins can edit any exam, teachers can only edit their own)
    if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to edit this exam', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        custom_name = request.form.get('custom_name', '').strip()
        beks = [b.strip() for b in request.form.getlist('bek[]') if b.strip()]
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        
        # Get custom tools
        tool_names = request.form.getlist('tool_name[]')
        tool_urls = request.form.getlist('tool_url[]')
        tool_ids = request.form.getlist('tool_id[]')
        tool_icons = request.form.getlist('tool_icon[]')
        
        # Build tools list
        tools = []
        for i in range(len(tool_names)):
            if tool_names[i] and tool_urls[i]:
                tools.append({
                    'id': tool_ids[i] if i < len(tool_ids) else str(uuid.uuid4()),
                    'name': tool_names[i],
                    'url': tool_urls[i],
                    'icon': tool_icons[i] if i < len(tool_icons) else 'bi-app'
                })
        
        if not tools:
            flash('At least one tool must be added', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))
        
        # Update exam entry (preserve exam_key and user_id)
        EXAMS[exam_id] = {
            'exam_key': EXAMS[exam_id]['exam_key'],  # Keep original exam_key
            'user_id': EXAMS[exam_id].get('user_id'),  # Keep original user_id
            'custom_name': custom_name,
            'beks': beks,
            'ck': ck,
            'ua': ua,
            'tools': tools
        }
        
        # Save to file
        save_exams(EXAMS)
        
        flash(f'Exam "{exam_id}" updated successfully!', 'success')
        return redirect(url_for('index'))
    
    return render_template('edit.html', exam_id=exam_id, exam=EXAMS[exam_id], exam_apps=EXAM_APPS)

@app.route('/delete/<exam_id>', methods=['POST'])
@login_required
def delete_exam(exam_id):
    """Delete an exam"""
    if exam_id in EXAMS:
        # Check ownership (admins can delete any exam, teachers can only delete their own)
        if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
            flash('You do not have permission to delete this exam', 'error')
            return redirect(url_for('index'))
        
        del EXAMS[exam_id]
        save_exams(EXAMS)
        flash(f'Exam deleted successfully!', 'success')
    else:
        flash(f'Exam not found', 'error')
    
    return redirect(url_for('index'))

@app.route('/exam/<exam_id>/details')
@login_required
def exam_details(exam_id):
    """Show exam details including generated keys"""
    if exam_id not in EXAMS:
        flash(f'Exam not found', 'error')
        return redirect(url_for('index'))
    
    # Check ownership
    if EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to view this exam', 'error')
        return redirect(url_for('index'))
    
    exam_data = EXAMS[exam_id]
    exam_url = url_for('exam', exam_id=exam_id, _external=True)
    
    return render_template(
        'exam_details.html',
        exam_id=exam_id,
        exam=exam_data,
        exam_url=exam_url
    )

@app.route('/api/exams')
@login_required
def api_exams():
    """API endpoint to get all exams as JSON"""
    # Admins see all exams, teachers see only their own
    if session.get('role') == 'admin':
        return jsonify(EXAMS)
    else:
        user_id = session.get('user_id')
        user_exams = {exam_id: exam for exam_id, exam in EXAMS.items() if exam.get('user_id') == user_id}
        return jsonify(user_exams)

# Admin Dashboard Routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard showing all users and exams"""
    return render_template('admin_dashboard.html', users=USERS, exams=EXAMS)

@app.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Create a new user account"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'teacher')
        
        # Validation
        if not username or not password or not name:
            flash('Username, password, and name are required', 'error')
            return redirect(url_for('admin_create_user'))
        
        if username in USERS:
            flash(f'Username "{username}" already exists', 'error')
            return redirect(url_for('admin_create_user'))
        
        if role not in ['admin', 'teacher']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('admin_create_user'))
        
        # Create user
        USERS[username] = {
            'user_id': str(uuid.uuid4()),
            'password_hash': generate_password_hash(password),
            'name': name,
            'role': role
        }
        
        save_users(USERS)
        flash(f'User "{username}" created successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_create_user.html')

@app.route('/admin/users/<username>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(username):
    """Edit an existing user account"""
    if username not in USERS:
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'teacher')
        new_password = request.form.get('new_password', '').strip()
        
        # Validation
        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('admin_edit_user', username=username))
        
        if role not in ['admin', 'teacher']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('admin_edit_user', username=username))
        
        # Update user
        USERS[username]['name'] = name
        USERS[username]['role'] = role
        
        # Update password if provided
        if new_password:
            USERS[username]['password_hash'] = generate_password_hash(new_password)
        
        save_users(USERS)
        flash(f'User "{username}" updated successfully!', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('admin_edit_user.html', username=username, user=USERS[username])

@app.route('/admin/users/<username>/delete', methods=['POST'])
@admin_required
def admin_delete_user(username):
    """Delete a user account"""
    if username not in USERS:
        flash('User not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Prevent deleting self
    if username == session.get('username'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('admin_dashboard'))
    
    del USERS[username]
    save_users(USERS)
    flash(f'User "{username}" deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
