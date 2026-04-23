import base64
from datetime import UTC, datetime, timedelta
import hmac
import re
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

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.]{3,32}$")


@event.listens_for(engine, "connect")
def enable_foreign_keys(dbapi_connection, _):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


@app.route("/api")
def check():
    return jsonify({"status": "ok"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})
    
    username = data.get("username")
    password = data.get("password")
    public_key_b64 = data.get("public_key")

    if not username or not password or not public_key_b64:
        return jsonify({"status": "error", "error": "Invalid input"})
    
    if len(username) > 50 or not USERNAME_REGEX.fullmatch(username):
        return jsonify({"status": "error", "error": "Invalid username"})

    try:
        public_key = base64.b64decode(public_key_b64)
        if len(public_key) != 32:
            raise ValueError()

    except Exception:
        return jsonify({"status": "error", "error": "Invalid public_key"})

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
        user = session.query(models.User).filter(models.User.username==username).first()

        if not user:
            return jsonify({"status": "error", "error": "Invalid credentials"})

        try:
            ph.verify(user.password_hash, password)
        except:
            return jsonify({"status": "error", "error": "Invalid credentials"})

        token = secrets.token_hex(32)
        
        hashed_token = hashlib.sha256(token.encode()).digest()

        session_obj = models.SessionModel(hashed_token=hashed_token, user_id=user.id, expires_at=datetime.utcnow() + timedelta(hours=12))

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

        if s.expires_at < datetime.utcnow():
            session.delete(s)
            session.commit()
            return None

        return s.user


@app.route("/api/get_user", methods=["GET"])
def get_user():
    data = request.args
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})

    token = data.get("token")
    username = data.get("username")

    if not token or not username:
        return jsonify({"status": "error", "error": "Invalid input"})

    user = get_user_from_token(token)

    if not user:
        return jsonify({"status": "error", "error": "Invalid session"})

    with Session(engine) as session:
        db_user = session.query(models.User).filter(models.User.username == username).first()

        if not db_user:
            return jsonify({"status": "error", "error": "User not found"})

        return {
            "status": "ok",
            "user": {
                "id": db_user.id,
                "username": db_user.username,
                "last_online": db_user.last_online.isoformat(),
                "public_key": base64.b64encode(db_user.public_key).decode()
            }
        }


@app.route("/api/create_chat", methods=["POST"])
def create_chat():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "No JSON"})

    token = data.get("token")
    chat_name = data.get("chat_name")
    keys = data.get("keys")

    users = list(keys.keys())

    if not token or not chat_name or not keys:
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
    models.Base.metadata.create_all(engine)

    socketio.run(app, host="127.0.0.1", port=5000)
    
