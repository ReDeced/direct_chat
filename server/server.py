import secrets
import models
import hashlib
from argon2 import PasswordHasher
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session
from flask import Flask, jsonify, request
from nacl.public import PrivateKey, Box

ph = PasswordHasher()
app = Flask(__name__)
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
        if session.query(models.User).filter(models.User.username == username).count() == 0:
            user = models.User(username=username, password_hash=password_hash, public_key=public_key)

            session.add(user)
            session.commit()

            return jsonify({"status": "ok"})

        else:
            return jsonify({"status": "error", "error": "User with this username already exists"})


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
        
        session = models.SessionModel(token=token, user_id=user.id)

        return jsonify({
            "status": "ok",
            "token": token
        })


def get_user_from_token(token):
    with Session(engine) as session:
        s = session.query(models.SessionModel).filter_by(token=token).first()
        return s.user if s else None

