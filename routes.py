from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session
import hashlib, uuid
from datetime import datetime
from models import (EXAMS, EXAM_APPS, USERS, EXAM_ATTEMPTS, 
                    save_exams, save_users, log_exam_attempt)
from utils import generate_exam_id, generate_exam_key, exam_id_exists, exam_key_exists
from auth import login_required, admin_required
from werkzeug.security import generate_password_hash
import os

routes_bp = Blueprint('routes', __name__)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')

@routes_bp.route('/')
@login_required
def index():
    """Home page showing all registered exams"""
    if session.get('role') == 'admin':
        user_exams = EXAMS
    else:
        user_id = session.get('user_id')
        user_exams = {exam_id: exam for exam_id, exam in EXAMS.items() if exam.get('user_id') == user_id}
    
    return render_template('index.html', exams=user_exams)

@routes_bp.route('/hash_generator')
def hash_generator():
    return render_template('hash_generator.html')

@routes_bp.route('/<exam_id>/exam')
def exam(exam_id):
    """Render the exam launcher page with available apps"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('routes.index'))
    
    exam_data = EXAMS[exam_id]
    
    if 'google_id' in session or 'email' in session:
        user_info = {
            'google_id': session.get('google_id', 'anonymous'),
            'email': session.get('email', 'anonymous@exam.local'),
            'name': session.get('name', 'Anonymous User')
        }
        log_exam_attempt(exam_id, user_info, 'exam_launch')
    
    tools = exam_data.get('tools', [])
    
    seb = {
        'beks': exam_data.get('beks', [exam_data.get('bek', '')]),
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256((url_for('routes.exam', exam_id=exam_id, _external=True)+exam_data.get('ua', '')).encode('utf-8')).hexdigest()
    }
    
    return render_template(
        'exam_launcher.html',
        exam_id=exam_id,
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        apps=tools,
        google_client_id=GOOGLE_CLIENT_ID
    )

@routes_bp.route('/<exam_id>/app/<app_id>')
def exam_app(exam_id, app_id):
    """Render the exam app page with specific app"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('routes.index'))
    
    exam_data = EXAMS[exam_id]
    
    tool = None
    for t in exam_data.get('tools', []):
        if t['id'] == app_id:
            tool = t
            break
    
    if not tool:
        flash(f'Tool not found', 'error')
        return redirect(url_for('routes.exam', exam_id=exam_id))
    
    if 'google_id' in session or 'email' in session:
        user_info = {
            'google_id': session.get('google_id', 'anonymous'),
            'email': session.get('email', 'anonymous@exam.local'),
            'name': session.get('name', 'Anonymous User')
        }
        log_exam_attempt(exam_id, user_info, f'tool_access:{tool["name"]}')
    
    seb = {
        'beks': exam_data.get('beks', [exam_data.get('bek', '')]),
        'ck': exam_data.get('ck', ''),
        'ua': hashlib.sha256((url_for('routes.exam_app', exam_id=exam_id, app_id=app_id, _external=True)+exam_data.get('ua', '')).encode('utf-8')).hexdigest()
    }
    
    return render_template(
        'exam_app.html',
        exam_id=exam_id,
        exam_key=exam_data.get('exam_key', exam_id),
        seb=seb,
        iframe_url=tool['url'],
        app_name=tool['name'],
        google_client_id=GOOGLE_CLIENT_ID
    )

@routes_bp.route('/exam/<exam_id>/quit')
def exam_quit(exam_id):
    """Specialized quit URL for Safe Exam Browser lockdown"""
    if exam_id not in EXAMS:
        return render_template('exam_quit.html', exam_found=False, exam_id=exam_id)
    
    exam_data = EXAMS[exam_id]
    return render_template('exam_quit.html', 
                          exam_found=True, 
                          exam_id=exam_id,
                          exam_key=exam_data.get('exam_key', exam_id))

@routes_bp.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    """Register a new exam"""
    if request.method == 'POST':
        beks = [b.strip() for b in request.form.getlist('bek[]') if b.strip()]
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        custom_name = request.form.get('custom_name', '').strip()
        
        tool_names = request.form.getlist('tool_name[]')
        tool_urls = request.form.getlist('tool_url[]')
        tool_ids = request.form.getlist('tool_id[]')
        tool_icons = request.form.getlist('tool_icon[]')
        tool_open_new_tab = request.form.getlist('tool_open_new_tab[]')  # Get checked tool IDs
        
        tools = []
        for i in range(len(tool_names)):
            if tool_names[i] and tool_urls[i]:
                tool_id = tool_ids[i] if i < len(tool_ids) else str(uuid.uuid4())
                tools.append({
                    'id': tool_id,
                    'name': tool_names[i],
                    'url': tool_urls[i],
                    'icon': tool_icons[i] if i < len(tool_icons) else 'bi-app',
                    'open_in_new_tab': tool_id in tool_open_new_tab
                })
        
        if not tools:
            flash('At least one tool must be added', 'error')
            return redirect(url_for('routes.register'))
        
        exam_id = generate_exam_id()
        exam_key = generate_exam_key()
        attempts = 0
        while exam_key_exists(exam_key, EXAMS) and attempts < 100:
            exam_key = generate_exam_key()
            attempts += 1
        
        if attempts >= 100:
            flash('Failed to generate unique exam key. Please try again.', 'error')
            return redirect(url_for('routes.register'))
        
        EXAMS[exam_id] = {
            'exam_key': exam_key,
            'custom_name': custom_name,
            'user_id': session.get('user_id'),
            'beks': beks,
            'ck': ck,
            'ua': ua,
            'tools': tools
        }
        
        save_exams(EXAMS)
        
        flash(f'Exam registered successfully! Exam Key: {exam_key}', 'success')
        return redirect(url_for('routes.exam_details', exam_id=exam_id))
    
    return render_template('register.html', exam_apps=EXAM_APPS)

@routes_bp.route('/edit/<exam_id>', methods=['GET', 'POST'])
@login_required
def edit_exam(exam_id):
    """Edit an existing exam"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('routes.index'))
    
    if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to edit this exam', 'error')
        return redirect(url_for('routes.index'))
    
    if request.method == 'POST':
        custom_name = request.form.get('custom_name', '').strip()
        beks = [b.strip() for b in request.form.getlist('bek[]') if b.strip()]
        ck = request.form.get('ck', '').strip()
        ua = request.form.get('ua', '').strip()
        
        tool_names = request.form.getlist('tool_name[]')
        tool_urls = request.form.getlist('tool_url[]')
        tool_ids = request.form.getlist('tool_id[]')
        tool_icons = request.form.getlist('tool_icon[]')
        tool_open_new_tab = request.form.getlist('tool_open_new_tab[]')  # Get checked tool IDs
        
        tools = []
        for i in range(len(tool_names)):
            if tool_names[i] and tool_urls[i]:
                tool_id = tool_ids[i] if i < len(tool_ids) else str(uuid.uuid4())
                tools.append({
                    'id': tool_id,
                    'name': tool_names[i],
                    'url': tool_urls[i],
                    'icon': tool_icons[i] if i < len(tool_icons) else 'bi-app',
                    'open_in_new_tab': tool_id in tool_open_new_tab
                })
        
        if not tools:
            flash('At least one tool must be added', 'error')
            return redirect(url_for('routes.edit_exam', exam_id=exam_id))
        
        EXAMS[exam_id] = {
            'exam_key': EXAMS[exam_id]['exam_key'],
            'user_id': EXAMS[exam_id].get('user_id'),
            'custom_name': custom_name,
            'beks': beks,
            'ck': ck,
            'ua': ua,
            'tools': tools
        }
        
        save_exams(EXAMS)
        
        flash(f'Exam "{exam_id}" updated successfully!', 'success')
        return redirect(url_for('routes.index'))
    
    return render_template('edit.html', exam_id=exam_id, exam=EXAMS[exam_id], exam_apps=EXAM_APPS)

@routes_bp.route('/delete/<exam_id>', methods=['POST'])
@login_required
def delete_exam(exam_id):
    """Delete an exam"""
    if exam_id in EXAMS:
        if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
            flash('You do not have permission to delete this exam', 'error')
            return redirect(url_for('routes.index'))
        
        del EXAMS[exam_id]
        save_exams(EXAMS)
        flash(f'Exam deleted successfully!', 'success')
    else:
        flash(f'Exam not found', 'error')
    
    return redirect(url_for('routes.index'))

@routes_bp.route('/exam/<exam_id>/details')
@login_required
def exam_details(exam_id):
    """Show exam details including generated keys"""
    if exam_id not in EXAMS:
        flash(f'Exam not found', 'error')
        return redirect(url_for('routes.index'))
    
    if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to view this exam', 'error')
        return redirect(url_for('routes.index'))
    
    exam_data = EXAMS[exam_id]
    exam_url = url_for('routes.exam', exam_id=exam_id, _external=True)
    
    return render_template(
        'exam_details.html',
        exam_id=exam_id,
        exam=exam_data,
        exam_url=exam_url
    )

@routes_bp.route('/exam/<exam_id>/attempts')
@login_required
def exam_attempts(exam_id):
    """Show all attempts for a specific exam"""
    if exam_id not in EXAMS:
        flash(f'Exam not found', 'error')
        return redirect(url_for('routes.index'))
    
    if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to view this exam', 'error')
        return redirect(url_for('routes.index'))
    
    exam_data = EXAMS[exam_id]
    attempts = EXAM_ATTEMPTS.get(exam_id, [])
    
    sorted_attempts = sorted(attempts, key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return render_template(
        'exam_attempts.html',
        exam_id=exam_id,
        exam=exam_data,
        attempts=sorted_attempts
    )

@routes_bp.route('/api/exams')
@login_required
def api_exams():
    """API endpoint to get all exams as JSON"""
    if session.get('role') == 'admin':
        return jsonify(EXAMS)
    else:
        user_id = session.get('user_id')
        user_exams = {exam_id: exam for exam_id, exam in EXAMS.items() if exam.get('user_id') == user_id}
        return jsonify(user_exams)

@routes_bp.route('/admin')
@admin_required
def admin_dashboard():
    """Admin dashboard showing all users and exams"""
    return render_template('admin_dashboard.html', users=USERS, exams=EXAMS)

@routes_bp.route('/admin/users/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Create a new user account"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'teacher')
        
        if not username or not password or not name:
            flash('Username, password, and name are required', 'error')
            return redirect(url_for('routes.admin_create_user'))
        
        if username in USERS:
            flash(f'Username "{username}" already exists', 'error')
            return redirect(url_for('routes.admin_create_user'))
        
        if role not in ['admin', 'teacher']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('routes.admin_create_user'))
        
        USERS[username] = {
            'user_id': str(uuid.uuid4()),
            'password_hash': generate_password_hash(password),
            'name': name,
            'role': role
        }
        
        save_users(USERS)
        flash(f'User "{username}" created successfully!', 'success')
        return redirect(url_for('routes.admin_dashboard'))
    
    return render_template('admin_create_user.html')

@routes_bp.route('/admin/users/<username>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(username):
    """Edit an existing user account"""
    if username not in USERS:
        flash('User not found', 'error')
        return redirect(url_for('routes.admin_dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        role = request.form.get('role', 'teacher')
        new_password = request.form.get('new_password', '').strip()
        
        if not name:
            flash('Name is required', 'error')
            return redirect(url_for('routes.admin_edit_user', username=username))
        
        if role not in ['admin', 'teacher']:
            flash('Invalid role selected', 'error')
            return redirect(url_for('routes.admin_edit_user', username=username))
        
        USERS[username]['name'] = name
        USERS[username]['role'] = role
        
        if new_password:
            USERS[username]['password_hash'] = generate_password_hash(new_password)
        
        save_users(USERS)
        flash(f'User "{username}" updated successfully!', 'success')
        return redirect(url_for('routes.admin_dashboard'))
    
    return render_template('admin_edit_user.html', username=username, user=USERS[username])

@routes_bp.route('/admin/users/<username>/delete', methods=['POST'])
@admin_required
def admin_delete_user(username):
    """Delete a user account"""
    if username not in USERS:
        flash('User not found', 'error')
        return redirect(url_for('routes.admin_dashboard'))
    
    if username == session.get('username'):
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('routes.admin_dashboard'))
    
    del USERS[username]
    save_users(USERS)
    flash(f'User "{username}" deleted successfully!', 'success')
    return redirect(url_for('routes.admin_dashboard'))
