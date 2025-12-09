#!/usr/bin/env python3
"""
SEB Pages - Safe Exam Browser Exam Management System
Main entry point for the Flask application.

All application logic has been refactored into modular components:
- __init__.py: Flask app initialization and blueprint registration
- auth.py: Authentication and authorization (login, OAuth, decorators)
- routes.py: Main application routes (exams, admin, API endpoints)
- models.py: Data layer (load/save JSON, exam attempt logging)
- utils.py: Utility functions (key generation, validation)
"""

from __init__ import app, socketio

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
