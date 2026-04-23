import base64
from datetime import datetime
import os
import requests
import models
from nacl.public import PrivateKey
from nacl.secret import SecretBox
from argon2.low_level import hash_secret_raw, Type
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

engine = create_engine("sqlite:///db.sqlite")
host = "http://127.0.0.1:5000"

current_session = {}


def get_derive_key(password: str, salt: bytes):
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )


def encrypt_private_key(private_bytes: bytes, password: str):
    salt = os.urandom(16)
    key = get_derive_key(password, salt)

    box = SecretBox(key)
    encrypted = box.encrypt(private_bytes)

    return salt, encrypted


def decrypt_private_key(encrypted: bytes, password: str, salt: bytes):
    key = get_derive_key(password, salt)

    box = SecretBox(key)
    private_bytes = box.decrypt(encrypted)

    return PrivateKey(private_bytes)


def check():
    response = requests.get(host + "/api").json()
    return response


def register(username: str, password: str):
    private_key = PrivateKey.generate()
    public_key = private_key.public_key
    data = {
        "username": username,
        "password": password,
        "public_key": base64.b64encode(bytes(public_key)).decode()
    }
    response = requests.post(host + "/api/register", json=data).json()
    
    if response.get("status") == "error":
        return response
    
    salt, encrypted_pk = encrypt_private_key(bytes(private_key), password)

    with Session(engine) as session:
        user_db = session.query(models.User).filter(models.User.username == username).first()
        if not user_db:
            user_db = models.User(
                username=username,
                public_key=bytes(public_key)
            )

        account_db = models.Account(
            salt=salt,
            encrypted_private_key=encrypted_pk,
            user=user_db
        )
        
        session.add_all([user_db, account_db])
        session.commit()

    return response


def get_token():
    token = current_session.get("token")

    if not token:
        raise RuntimeError("You need to login first")

    return token


def get_user(username: str):
    token = get_token()

    data = {
        "token": token,
        "username": username
    }
    response = requests.get(host + "/api/get_user", params=data).json()

    if response.get("status") == "error":
        return response.get("error")
    
    user_data = response.get("user")
    if not user_data:
        return {"status": "error", "error": "Server did not provide any user data"}

    user = {
        "server_id": user_data.get("id"),
        "username": user_data.get("username"),
        "last_online": datetime.fromisoformat(user_data.get("last_online")),
        "public_key": base64.b64decode(user_data.get("public_key"))
    }

    return user


def login(username: str, password: str):
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(host + "/api/login", json=data).json()
    if response.get("status") == "error":
        return response.get("error")

    token = response.get("token")

    if not token:
        return {"status": "error", "error": "Server did not provide token"}

    current_session["token"] = response.get("token")

    return response


def create_chat(chat_name: str, keys: dict[str, bytes]):
    token = get_token()

    group_key = os.urandom(32)
    


def main():
    models.Base.metadata.create_all(engine)
    ...


if __name__ == "__main__":
    main()


