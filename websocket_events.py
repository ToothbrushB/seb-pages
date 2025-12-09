"""
WebSocket event handlers for real-time communication
Handles student focus tracking, teacher messaging, and remote control
"""
from flask import session, request
from flask_socketio import emit, join_room, leave_room, rooms
from datetime import datetime
import json

# Store active student sessions
# Format: {exam_id: {session_id: {user_info, focused_window, last_ping, socket_id}}}
active_students = {}

def init_socketio(socketio):
    """Initialize all SocketIO event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        print(f"Client connected: {request.sid}")
        emit('connected', {'sid': request.sid})
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection and cleanup"""
        print(f"Client disconnected: {request.sid}")
        
        # Clean up student tracking
        for exam_id in list(active_students.keys()):
            for session_id in list(active_students[exam_id].keys()):
                if active_students[exam_id][session_id].get('socket_id') == request.sid:
                    del active_students[exam_id][session_id]
                    # Notify teachers about disconnection
                    socketio.emit('student_disconnected', {
                        'exam_id': exam_id,
                        'session_id': session_id
                    }, room=f'teacher_{exam_id}')
            
            # Clean up empty exam entries
            if not active_students[exam_id]:
                del active_students[exam_id]
    
    @socketio.on('join_exam_student')
    def handle_join_exam_student(data):
        """Student joins an exam room for real-time updates"""
        exam_id = data.get('exam_id')
        user_info = data.get('user_info', {})
        window_type = data.get('window_type', 'unknown')  # 'launcher' or 'app'
        tool_name = data.get('tool_name', '')  # Name of the tool if in app window
        
        if not exam_id:
            return
        
        # Create session ID from user info or socket ID
        session_id = user_info.get('email', request.sid)
        
        # Join the exam room
        room_name = f'exam_{exam_id}'
        join_room(room_name)
        
        # Track this student
        if exam_id not in active_students:
            active_students[exam_id] = {}
        
        active_students[exam_id][session_id] = {
            'user_info': user_info,
            'focused_window': window_type,
            'last_ping': datetime.utcnow().isoformat(),
            'last_keypress': datetime.utcnow().isoformat(),
            'socket_id': request.sid,
            'window_type': window_type,
            'tool_name': tool_name,
            'needs_help': False
        }
        
        # Notify teachers
        socketio.emit('student_joined', {
            'exam_id': exam_id,
            'session_id': session_id,
            'user_info': user_info,
            'window_type': window_type,
            'tool_name': tool_name
        }, room=f'teacher_{exam_id}')
        
        emit('joined_exam', {'exam_id': exam_id, 'session_id': session_id})
    
    @socketio.on('join_exam_teacher')
    def handle_join_exam_teacher(data):
        """Teacher joins an exam room to monitor students"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        # Join teacher-specific room
        room_name = f'teacher_{exam_id}'
        join_room(room_name)
        
        # Send current student list
        students_list = []
        if exam_id in active_students:
            for session_id, student_data in active_students[exam_id].items():
                students_list.append({
                    'session_id': session_id,
                    'user_info': student_data['user_info'],
                    'focused_window': student_data['focused_window'],
                    'last_ping': student_data['last_ping'],
                    'last_keypress': student_data.get('last_keypress'),
                    'window_type': student_data['window_type'],
                    'tool_name': student_data.get('tool_name', 'Launcher'),
                    'needs_help': student_data.get('needs_help', False)
                })
        
        emit('current_students', {'students': students_list})
    
    @socketio.on('student_focus_update')
    def handle_focus_update(data):
        """Update which window the student has focused"""
        exam_id = data.get('exam_id')
        window_type = data.get('window_type')  # 'launcher', 'app', or 'other'
        is_focused = data.get('is_focused', False)
        tool_name = data.get('tool_name', '')
        
        if not exam_id:
            return
        
        # Find this student's session
        for session_id, student_data in active_students.get(exam_id, {}).items():
            if student_data.get('socket_id') == request.sid:
                student_data['focused_window'] = window_type if is_focused else 'other'
                student_data['last_ping'] = datetime.utcnow().isoformat()
                if tool_name:
                    student_data['tool_name'] = tool_name
                
                # Notify teachers
                socketio.emit('student_focus_changed', {
                    'exam_id': exam_id,
                    'session_id': session_id,
                    'focused_window': student_data['focused_window'],
                    'tool_name': student_data.get('tool_name', ''),
                    'user_info': student_data['user_info']
                }, room=f'teacher_{exam_id}')
                break
    
    @socketio.on('student_ping')
    def handle_student_ping(data):
        """Heartbeat ping from student"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        # Update last ping time
        for session_id, student_data in active_students.get(exam_id, {}).items():
            if student_data.get('socket_id') == request.sid:
                student_data['last_ping'] = datetime.utcnow().isoformat()
                break
        
        # Send pong
        emit('pong', {'timestamp': datetime.utcnow().isoformat()})
    
    @socketio.on('teacher_send_message')
    def handle_teacher_message(data):
        """Teacher sends a message to all students in an exam"""
        exam_id = data.get('exam_id')
        message = data.get('message', '')
        title = data.get('title', 'Message from Teacher')
        
        if not exam_id or not message:
            return
        
        # Send to all students in the exam
        socketio.emit('teacher_message', {
            'title': title,
            'message': message,
            'timestamp': datetime.utcnow().isoformat()
        }, room=f'exam_{exam_id}')
        
        # Confirm to teacher
        emit('message_sent', {'success': True})
    
    @socketio.on('student_keypress')
    def handle_student_keypress(data):
        """Update last keypress time for student"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        # Update last keypress time
        for session_id, student_data in active_students.get(exam_id, {}).items():
            if student_data.get('socket_id') == request.sid:
                student_data['last_keypress'] = datetime.utcnow().isoformat()
                student_data['last_ping'] = datetime.utcnow().isoformat()
                break
    
    @socketio.on('student_request_help')
    def handle_student_help_request(data):
        """Student requests help from teacher"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        # Update help flag
        for session_id, student_data in active_students.get(exam_id, {}).items():
            if student_data.get('socket_id') == request.sid:
                student_data['needs_help'] = True
                
                # Notify teachers
                socketio.emit('student_needs_help', {
                    'exam_id': exam_id,
                    'session_id': session_id,
                    'user_info': student_data['user_info']
                }, room=f'teacher_{exam_id}')
                
                emit('help_request_sent', {'success': True})
                break
    
    @socketio.on('teacher_clear_help_flag')
    def handle_clear_help_flag(data):
        """Teacher clears student's help flag"""
        exam_id = data.get('exam_id')
        session_id = data.get('session_id')
        
        if not exam_id or not session_id:
            return
        
        if exam_id in active_students and session_id in active_students[exam_id]:
            active_students[exam_id][session_id]['needs_help'] = False
            
            # Notify all teachers monitoring this exam
            socketio.emit('help_flag_cleared', {
                'exam_id': exam_id,
                'session_id': session_id
            }, room=f'teacher_{exam_id}')
            
            emit('help_flag_cleared_success', {'success': True})
    
    @socketio.on('teacher_send_individual_message')
    def handle_teacher_individual_message(data):
        """Teacher sends a message to a specific student"""
        exam_id = data.get('exam_id')
        session_id = data.get('session_id')
        message = data.get('message', '')
        title = data.get('title', 'Message from Teacher')
        
        if not exam_id or not session_id or not message:
            return
        
        # Find the student's socket ID
        if exam_id in active_students and session_id in active_students[exam_id]:
            student_socket_id = active_students[exam_id][session_id].get('socket_id')
            if student_socket_id:
                # Send to specific student
                socketio.emit('teacher_message', {
                    'title': title,
                    'message': message,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=student_socket_id)
                
                emit('message_sent', {'success': True})
            else:
                emit('message_sent', {'success': False, 'error': 'Student not connected'})
        else:
            emit('message_sent', {'success': False, 'error': 'Student not found'})
    
    @socketio.on('teacher_redirect_individual')
    def handle_teacher_individual_redirect(data):
        """Teacher redirects a specific student to quit URL"""
        exam_id = data.get('exam_id')
        session_id = data.get('session_id')
        
        if not exam_id or not session_id:
            return
        
        # Find the student's socket ID
        if exam_id in active_students and session_id in active_students[exam_id]:
            student_socket_id = active_students[exam_id][session_id].get('socket_id')
            if student_socket_id:
                # Send redirect command to specific student
                socketio.emit('redirect_to_quit', {
                    'url': f'/exam/{exam_id}/quit'
                }, room=student_socket_id)
                
                emit('redirect_sent', {'success': True})
            else:
                emit('redirect_sent', {'success': False, 'error': 'Student not connected'})
        else:
            emit('redirect_sent', {'success': False, 'error': 'Student not found'})
    
    @socketio.on('teacher_redirect_students')
    def handle_teacher_redirect(data):
        """Teacher redirects all students to quit URL"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        # Send redirect command to all students
        socketio.emit('redirect_to_quit', {
            'url': f'/exam/{exam_id}/quit'
        }, room=f'exam_{exam_id}')
        
        # Confirm to teacher
        emit('redirect_sent', {'success': True})
    
    @socketio.on('get_active_students')
    def handle_get_active_students(data):
        """Teacher requests current list of active students"""
        exam_id = data.get('exam_id')
        
        if not exam_id:
            return
        
        students_list = []
        if exam_id in active_students:
            for session_id, student_data in active_students[exam_id].items():
                students_list.append({
                    'session_id': session_id,
                    'user_info': student_data['user_info'],
                    'focused_window': student_data['focused_window'],
                    'last_ping': student_data['last_ping'],
                    'window_type': student_data['window_type']
                })
        
        emit('active_students_list', {'students': students_list})
    
    return socketio
