from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, session, send_file
import hashlib, uuid, json, plistlib
from datetime import datetime
from models import (EXAMS, EXAM_APPS, USERS, EXAM_ATTEMPTS, 
                    save_exams, save_users, log_exam_attempt)
from utils import generate_exam_id, generate_exam_key, exam_id_exists, exam_key_exists
from auth import login_required, admin_required
from werkzeug.security import generate_password_hash
from sebConfigUtils import encrypt_seb_config, generate_config_key, create_seb_from_json
import os

routes_bp = Blueprint('routes', __name__)
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', 'YOUR_GOOGLE_CLIENT_ID_HERE')

def generate_seb_file(exam_id, exam_password, quit_password, user_agent):
    """Generate a .seb config file for the exam"""
    # Load template
    template_path = os.path.join(os.path.dirname(__file__), 'sebConfigTemplate.json')
    with open(template_path, 'r', encoding='utf-8') as f:
        config = json.load(f)
    
    # Set startURL
    exam_url = url_for('routes.exam', exam_id=exam_id, _external=True)
    config['startURL'] = exam_url
    
    # Set user agent strings wrapped in []
    config['browserUserAgent'] = f"[{user_agent}]"
    config['browserUserAgentiOSCustom'] = f"[{user_agent}]"
    config['browserUserAgentMacCustom'] = f"[{user_agent}]"
    config['browserUserAgentWinDesktopModeCustom'] = f"[{user_agent}]"
    config['browserUserAgentWinTouchModeCustom'] = f"[{user_agent}]"
    config['browserUserAgentWinTouchModeIPad'] = f"[{user_agent}]"
    
    config['quitURL'] = url_for('routes.exam_quit', exam_id=exam_id, _external=True)
    # Hash quit password with SHA256
    hashed_quit = hashlib.sha256(quit_password.encode('utf-8')).hexdigest()
    config['hashedQuitPassword'] = hashed_quit
    
    (seb_data, config_key) = create_seb_from_json(config, password=exam_password, debug=False)

    
    return (seb_data, config_key)

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
    
    # Check if exam is enabled (default to True for backwards compatibility)
    if not exam_data.get('enabled', True):
        return render_template('exam_quit.html', 
                             message='This exam is currently disabled',
                             reason='The exam has been disabled by the instructor. Please contact your instructor for more information.')
    
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
        custom_name = request.form.get('custom_name', '').strip()
        exam_password = request.form.get('exam_password', '').strip()
        quit_password = request.form.get('quit_password', '').strip()
        
        if not exam_password or not quit_password:
            flash('Exam password and quit password are required', 'error')
            return redirect(url_for('routes.register'))
        
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
        
        ua = os.urandom(100).hex()
        # Generate SEB file
        try:
            (seb_data, config_key) = generate_seb_file(exam_id, exam_password, quit_password, ua)
            
            # Save SEB file to disk
            seb_dir = os.path.join(os.path.dirname(__file__), 'seb_files')
            os.makedirs(seb_dir, exist_ok=True)
            seb_path = os.path.join(seb_dir, f'{exam_id}.seb')
            
            with open(seb_path, 'wb') as f:
                f.write(seb_data)
        except Exception as e:
            flash(f'Failed to generate SEB file: {str(e)}', 'error')
            return redirect(url_for('routes.register'))
        
        EXAMS[exam_id] = {
            'exam_key': exam_key,
            'custom_name': custom_name,
            'user_id': session.get('user_id'),
            'beks': beks,
            'ck': config_key,
            'ua': ua,
            'tools': tools,
            'seb_file': f'{exam_id}.seb',
            'enabled': request.form.get('enabled') == 'on'
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
        exam_password = request.form.get('exam_password', '').strip()
        quit_password = request.form.get('quit_password', '').strip()
        
        # Regenerate SEB file if passwords provided
        regenerate_seb = bool(exam_password and quit_password)
        
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
        
        # Regenerate SEB file if passwords were provided
        ua = EXAMS[exam_id].get('ua', os.urandom(100).hex())
        seb_file = EXAMS[exam_id].get('seb_file', f'{exam_id}.seb')
        if regenerate_seb:
            try:
                (seb_data, config_key) = generate_seb_file(exam_id, exam_password, quit_password, ua)
                
                # Save SEB file to disk
                seb_dir = os.path.join(os.path.dirname(__file__), 'seb_files')
                os.makedirs(seb_dir, exist_ok=True)
                seb_path = os.path.join(seb_dir, seb_file)
                
                with open(seb_path, 'wb') as f:
                    f.write(seb_data)
                    
                flash('SEB config file regenerated successfully!', 'success')
            except Exception as e:
                flash(f'Failed to regenerate SEB file: {str(e)}', 'error')
        
        EXAMS[exam_id] = {
            'exam_key': EXAMS[exam_id]['exam_key'],
            'user_id': EXAMS[exam_id].get('user_id'),
            'custom_name': custom_name,
            'beks': beks,
            'ck': config_key if regenerate_seb else EXAMS[exam_id].get('ck', ''),
            'ua': ua,
            'tools': tools,
            'seb_file': seb_file
        }
        
        save_exams(EXAMS)
        
        flash(f'Exam "{exam_id}" updated successfully!', 'success')
        return redirect(url_for('routes.index'))
    
    return render_template('edit.html', exam_id=exam_id, exam=EXAMS[exam_id], exam_apps=EXAM_APPS)

@routes_bp.route('/exam/<exam_id>/download')
@login_required
def download_seb(exam_id):
    """Download the SEB config file for an exam"""
    if exam_id not in EXAMS:
        flash(f'Exam "{exam_id}" not found', 'error')
        return redirect(url_for('routes.index'))
    
    # Check permissions
    if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
        flash('You do not have permission to download this SEB file', 'error')
        return redirect(url_for('routes.index'))
    
    exam = EXAMS[exam_id]
    seb_file = exam.get('seb_file', f'{exam_id}.seb')
    seb_path = os.path.join(os.path.dirname(__file__), 'seb_files', seb_file)
    
    if not os.path.exists(seb_path):
        flash('SEB file not found. Please regenerate it by editing the exam.', 'error')
        return redirect(url_for('routes.exam_details', exam_id=exam_id))
    
    # Use custom name or exam key as filename
    download_name = exam.get('custom_name', exam.get('exam_key', exam_id))
    download_name = download_name.replace(' ', '_') + '.seb'
    
    return send_file(seb_path, as_attachment=True, download_name=download_name)

@routes_bp.route('/exam/<exam_id>/download/public')
def download_seb_public(exam_id):
    """Public download endpoint for students (no login required)"""
    if exam_id not in EXAMS:
        return "Exam not found", 404
    
    exam = EXAMS[exam_id]
    
    # Check if exam is enabled (default to True for backwards compatibility)
    if not exam.get('enabled', True):
        return "This exam is currently disabled", 403
    seb_file = exam.get('seb_file', f'{exam_id}.seb')
    seb_path = os.path.join(os.path.dirname(__file__), 'seb_files', seb_file)
    
    if not os.path.exists(seb_path):
        return "SEB file not found", 404
    
    # Use custom name or exam key as filename
    download_name = exam.get('custom_name', exam.get('exam_key', exam_id))
    download_name = download_name.replace(' ', '_') + '.seb'
    
    return send_file(seb_path, as_attachment=True, download_name=download_name)

@routes_bp.route('/delete/<exam_id>', methods=['POST'])
@login_required
def delete_exam(exam_id):
    """Delete an exam"""
    if exam_id in EXAMS:
        if session.get('role') != 'admin' and EXAMS[exam_id].get('user_id') != session.get('user_id'):
            flash('You do not have permission to delete this exam', 'error')
            return redirect(url_for('routes.index'))
        
        del EXAMS[exam_id]
        del EXAM_ATTEMPTS[exam_id]
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

@routes_bp.route('/api/exam-by-key')
def api_exam_by_key():
    """API endpoint to look up exam by 4-word key (public access for students)"""
    exam_key = request.args.get('key', '').strip().upper()
    
    if not exam_key:
        return jsonify({'success': False, 'error': 'No exam key provided'})
    
    # Find exam with matching key
    exam_id = None
    for eid, exam in EXAMS.items():
        if exam.get('exam_key', '').upper() == exam_key:
            exam_id = eid
            break
    
    if not exam_id:
        return jsonify({'success': False, 'error': 'Exam not found'})
    
    # Check if exam is enabled (default to True for backwards compatibility)
    if not EXAMS[exam_id].get('enabled', True):
        return jsonify({'success': False, 'error': 'This exam is currently disabled'})
    
    # Return download URLs
    download_url = url_for('routes.download_seb_public', exam_id=exam_id, _external=True)
    download_path = url_for('routes.download_seb_public', exam_id=exam_id)
    
    return jsonify({
        'success': True,
        'exam_id': exam_id,
        'exam_key': exam_key,
        'download_url': download_url,
        'download_path': download_path
    })

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

