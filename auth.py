from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import datetime
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os, uuid
from models import USERS, save_users

auth_bp = Blueprint('auth', __name__)

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', 'YOUR_GOOGLE_CLIENT_SECRET_HERE')

def login_required(f):
    """Decorator for routes requiring login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('auth.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator for routes requiring admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please login to access this page', 'error')
            return redirect(url_for('auth.login', next=request.url))
        
        username = session.get('username')
        if username not in USERS or USERS[username].get('role') != 'admin':
            flash('You do not have permission to access this page', 'error')
            return redirect(url_for('routes.index'))
        
        return f(*args, **kwargs)
    return decorated_function

@auth_bp.route('/login', methods=['GET', 'POST'])
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
                session['email'] = user.get('email', '')
                session['auth_method'] = 'password'
                flash(f'Welcome, {user.get("name", username)}!', 'success')
                
                next_page = request.args.get('next')
                if next_page:
                    return redirect(next_page)
                return redirect(url_for('routes.index'))
        
        flash('Invalid username or password', 'error')
        return redirect(url_for('auth.login'))
    
    if 'username' in session:
        return redirect(url_for('routes.index'))
    
    return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)

@auth_bp.route('/auth/google', methods=['POST'])
def google_auth():
    """Handle Google Sign-In callback"""
    try:
        token = request.json.get('credential')
        
        if not token:
            return jsonify({'success': False, 'error': 'No credential provided'}), 400
        
        try:
            idinfo = id_token.verify_oauth2_token(
                token, 
                google_requests.Request(), 
                GOOGLE_CLIENT_ID
            )
        except ValueError as e:
            return jsonify({'success': False, 'error': f'Invalid token: {str(e)}'}), 401
        
        google_id = idinfo['sub']
        email = idinfo.get('email', '')
        name = idinfo.get('name', email.split('@')[0])
        picture = idinfo.get('picture', '')
        
        existing_user = None
        existing_username = None
        
        for username, user_data in USERS.items():
            if user_data.get('google_id') == google_id or user_data.get('email') == email:
                existing_user = user_data
                existing_username = username
                break
        
        if existing_user:
            existing_user['google_id'] = google_id
            existing_user['email'] = email
            existing_user['name'] = name
            existing_user['picture'] = picture
            existing_user['last_login'] = datetime.utcnow().isoformat()
            
            username = existing_username
            user_id = existing_user.get('user_id')
            role = existing_user.get('role', 'teacher')
        else:
            username = email
            user_id = str(uuid.uuid4())
            role = 'teacher'
            
            USERS[username] = {
                'user_id': user_id,
                'google_id': google_id,
                'email': email,
                'name': name,
                'picture': picture,
                'role': role,
                'created_at': datetime.utcnow().isoformat(),
                'last_login': datetime.utcnow().isoformat(),
                'password_hash': None
            }
        
        save_users(USERS)
        
        session['username'] = username
        session['user_id'] = user_id
        session['name'] = name
        session['email'] = email
        session['role'] = role
        session['google_id'] = google_id
        session['picture'] = picture
        session['auth_method'] = 'google'
        
        next_page = request.args.get('next') or url_for('routes.index')
        
        return jsonify({
            'success': True, 
            'redirect': next_page,
            'name': name
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@auth_bp.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('user_id', None)
    session.pop('name', None)
    session.pop('role', None)
    session.pop('email', None)
    session.pop('google_id', None)
    session.pop('picture', None)
    session.pop('auth_method', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('auth.login'))
