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
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Home page showing all registered exams"""
    # Filter exams by current user
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
    
    # Get the list of app IDs for this exam
    app_ids = exam_data.get('apps', ['desmos-graphing'])
    
    # Build list of app details
    available_apps = []
    for app_id in app_ids:
        if app_id in EXAM_APPS:
            app_info = EXAM_APPS[app_id].copy()
            app_info['id'] = app_id
            available_apps.append(app_info)
    
    seb = {
        'bek': exam_data.get('bek', ''),
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256(url_for('exam', exam_id=exam_id)+exam_data.get('ua', '')).hexdigest()
    }
    
    return render_template(
        'exam_launcher.html',
        exam_id=exam_id,
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        apps=available_apps
    )

@app.route('/<exam_id>/app/<app_id>')
def exam_app(exam_id, app_id):
    """Render the exam app page with specific app"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('index'))
    
    if app_id not in EXAM_APPS:
        flash(f'App "{app_id}" not found', 'error')
        return redirect(url_for('exam', exam_id=exam_id))
    
    exam_data = EXAMS[exam_id]
    app_data = EXAM_APPS[app_id]
    
    # Prepare SEB data
    seb = {
        'bek': exam_data.get('bek', ''),
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256(url_for('exam_app', exam_id=exam_id, app_id=app_id)+exam_data.get('ua', '')).hexdigest()
    }
    
    return render_template(
        'exam_app.html',
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        iframe_url=app_data['url'],
        app_name=app_data['name']
    )

@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """Register a new exam"""
    if request.method == 'POST':
        bek = request.form.get('bek', '').strip()
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        
        # Get selected apps
        selected_apps = request.form.getlist('apps')
        
        # Validation
        if not selected_apps:
            flash('At least one app must be selected', 'error')
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
            'bek': bek,
            'ck': ck,
            'ua': ua,
            'apps': selected_apps
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
    
    # Check ownership
    if EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to edit this exam', 'error')
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        custom_name = request.form.get('custom_name', '').strip()
        bek = request.form.get('bek', '').strip()
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        
        # Get selected apps
        selected_apps = request.form.getlist('apps')
        
        if not selected_apps:
            flash('At least one app must be selected', 'error')
            return redirect(url_for('edit_exam', exam_id=exam_id))
        
        # Update exam entry (preserve exam_key and user_id)
        EXAMS[exam_id] = {
            'exam_key': EXAMS[exam_id]['exam_key'],  # Keep original exam_key
            'user_id': EXAMS[exam_id].get('user_id'),  # Keep original user_id
            'custom_name': custom_name,
            'bek': bek,
            'ck': ck,
            'ua': ua,
            'apps': selected_apps
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
        # Check ownership
        if EXAMS[exam_id].get('user_id') != session.get('user_id'):
            flash('You do not have permission to delete this exam', 'error')
            return redirect(url_for('index'))
        
        del EXAMS[exam_id]
        save_exams(EXAMS)
        flash(f'Exam "{exam_id}" deleted successfully!', 'success')
    else:
        flash(f'Exam "{exam_id}" not found', 'error')
    
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
    # Filter exams by current user
    user_id = session.get('user_id')
    user_exams = {exam_id: exam for exam_id, exam in EXAMS.items() if exam.get('user_id') == user_id}
    return jsonify(user_exams)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
