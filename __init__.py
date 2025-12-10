from flask import Flask
from flask_socketio import SocketIO
from auth import auth_bp
from routes import routes_bp
from models import load_exams, load_users, load_exam_apps, load_exam_attempts
import os

app = Flask(__name__)

# Configuration
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-in-production')
app.config['SECRET_KEY'] = app.secret_key
app.jinja_env.globals.update(iter=iter, next=next) 

# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Load all data on startup
load_exams()
load_users()
load_exam_apps()
load_exam_attempts()

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(routes_bp)

# Initialize WebSocket event handlers
from websocket_events import init_socketio
init_socketio(socketio)

@app.route('/favicon.ico')
def favicon():
    return app.send_static_file('favicon.ico')