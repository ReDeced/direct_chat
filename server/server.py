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
    
    password_hash = ph.hash(password)

    with Session(engine) as session:
        if session.query(models.User).filter(models.User.username == username).count() == 0:
            user = models.User(username=username, password_hash=password_hash, public_key=public_key)

            session.add(user)
            session.commit()

            return jsonify({"status": "ok"})

        else:
            return jsonify({"status": "error", "error": "User with this username already exists"})


