import json, os, uuid
from datetime import datetime

EXAM_DB_PATH = 'data/exams.json'
EXAM_APPS_PATH = 'data/exam_apps.json'
USERS_DB_PATH = 'data/users.json'
EXAM_ATTEMPTS_PATH = 'data/exam_attempts.json'

def load_exams():
    if os.path.exists(EXAM_DB_PATH):
        with open(EXAM_DB_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_exams(exams):
    with open(EXAM_DB_PATH, 'w') as f:
        json.dump(exams, f, indent=2)

def load_exam_apps():
    if os.path.exists(EXAM_APPS_PATH):
        with open(EXAM_APPS_PATH, 'r') as f:
            return json.load(f)
    return {}

def load_users():
    if os.path.exists(USERS_DB_PATH):
        with open(USERS_DB_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_DB_PATH, 'w') as f:
        json.dump(users, f, indent=2)

def load_exam_attempts():
    if os.path.exists(EXAM_ATTEMPTS_PATH):
        with open(EXAM_ATTEMPTS_PATH, 'r') as f:
            return json.load(f)
    return {}

def save_exam_attempts(attempts):
    with open(EXAM_ATTEMPTS_PATH, 'w') as f:
        json.dump(attempts, f, indent=2)

def log_exam_attempt(exam_id, user_info, access_type='exam_launch'):
    """Log when a user accesses an exam or exam tool."""
    attempts = load_exam_attempts()
    
    if exam_id not in attempts:
        attempts[exam_id] = []
    
    attempt_record = {
        'timestamp': datetime.utcnow().isoformat(),
        'google_id': user_info.get('google_id'),
        'email': user_info.get('email'),
        'name': user_info.get('name'),
        'access_type': access_type,
        'attempt_id': str(uuid.uuid4())
    }
    
    attempts[exam_id].append(attempt_record)
    save_exam_attempts(attempts)
    return attempt_record

# Initialize global data dictionaries
EXAMS = load_exams()
EXAM_APPS = load_exam_apps()
USERS = load_users()
EXAM_ATTEMPTS = load_exam_attempts()
