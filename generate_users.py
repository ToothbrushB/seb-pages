#!/usr/bin/env python3
from werkzeug.security import generate_password_hash
import json
import uuid

users = {
    "admin": {
        "user_id": str(uuid.uuid4()),
        "password_hash": generate_password_hash("admin"),
        "name": "Administrator"
    },
    "teacher": {
        "user_id": str(uuid.uuid4()),
        "password_hash": generate_password_hash("teacher"),
        "name": "Teacher"
    }
}

with open('users.json', 'w') as f:
    json.dump(users, f, indent=2)

print("Users file updated with UUIDs!")
print("Usernames and passwords:")
print("  admin / admin")
print("  teacher / teacher")
print("\nUser IDs:")
for username, data in users.items():
    print(f"  {username}: {data['user_id']}")
