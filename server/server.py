from datetime import UTC, datetime, timedelta
import hmac
import secrets
import models
import hashlib
from argon2 import PasswordHasher
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from flask import Flask, jsonify, request
from flask_socketio import SocketIO

ph = PasswordHasher()
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
engine = create_engine("sqlite:///db.sqlite")


@event.listens_for(engine, "connect")
def enable_foreign_keys(dbapi_connection, _):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@app.route("/api")
def api():
    return jsonify({"status": "ok"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})
    
    username = data.get("username")
    password = data.get("password")
    public_key = data.get("public_key")

    if not username or not password or not public_key:
        return jsonify({"status": "error", "error": "Invalid input"})
   
    password_hash = ph.hash(password)

    with Session(engine) as session:
        user = models.User(username=username, password_hash=password_hash, public_key=public_key)
        
        try:
            session.add(user)
            session.commit()
        
        except:
            return jsonify({"status": "error", "error": "User with this username already exists"})

        return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})

    username = data.get("username")
    password = data.get("password")
    
    if not username or not password:
        return jsonify({"status": "error", "error": "Invalid input"})
    
    with Session(engine) as session:
        user = session.query(models.User).filter_by(username=username).first()

        if not user:
            return jsonify({"status": "error", "error": "Invalid credentials"})

        try:
            ph.verify(user.password_hash, password)
        except:
            return jsonify({"status": "error", "error": "Invalid credentials"})

        token = secrets.token_hex(32)
        
        hashed_token = hashlib.sha256(token.encode()).digest()

        session_obj = models.SessionModel(hashed_token=hashed_token, user_id=user.id, expires_at=datetime.now(UTC) + timedelta(hours=12))

        session.add(session_obj)
        session.commit()

        return jsonify({
            "status": "ok",
            "token": token
        })


def verify_token(token, stored_hash):
    token_hash = hashlib.sha256(token.encode()).digest()
    return hmac.compare_digest(token_hash, stored_hash)


def get_user_from_token(token):
    token_hash = hashlib.sha256(token.encode()).digest()

    with Session(engine) as session:
        s = session.query(models.SessionModel).filter_by(hashed_token=token_hash).first()

        if not s:
            return None

        if s.expires_at < datetime.now(UTC):
            session.delete(s)
            session.commit()
            return None

        return s.user


@app.route("/api/create_chat", methods=["POST"])
def create_chat():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})

    token = data.get("token")
    chat_name = data.get("chat_name")
    users = data.get("users")
    group_key = data.get("group_key")
   
    if not token or chat_name or users or group_key:
        return jsonify({"status": "error", "error": "Invalid input"})
    
    user = get_user_from_token(token)

    if not user:
        return jsonify({"status": "error", "error": "Invalid session"})

    with Session(engine) as session:
        db_users = session.query(models.User).filter(models.User.username.in_(users)).all()

        if len(db_users) != len(users):
            return jsonify({"status": "error", "error": "Some users not found"})

        chat = models.Chat()
        session.add(chat)
        session.flush()

        session.add(models.ChatMembership(user_id=user.id, chat_id=chat.id))

        for u in db_users:
            if u.id == user.id:
                continue

            session.add(models.ChatMembership(user_id=u.id, chat_id=chat.id))

        session.commit()

        return jsonify({"status": "ok", "chat_id": chat.id})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)
    
