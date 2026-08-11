import base64
from datetime import datetime, timedelta, timezone
import hmac
import re
import secrets
import models
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from flask import Flask, jsonify, request
from flask_socketio import SocketIO, disconnect as socketio_disconnect, join_room, leave_room, emit

ph = PasswordHasher()
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
engine = create_engine("sqlite:///db.sqlite")

USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_.]{3,32}$")

# sid -> user_id: все активные WebSocket-соединения
connected_users: dict[str, int] = {}

# user_id -> set[sid]: один пользователь может быть подключён с нескольких устройств
user_sids: dict[int, set[str]] = {}


# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------

def utcnow() -> datetime:
    """Возвращает текущее время UTC (aware). datetime.utcnow() устарел в Python 3.12."""
    return datetime.now(timezone.utc)


def get_token_from_request() -> str | None:
    """
    Извлекает токен из заголовка Authorization: Bearer <token>.
    Токен не должен передаваться в URL — он попадает в логи сервера.
    """
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return None


def get_user_from_token(token: str) -> int | None:
    """
    Проверяет токен и возвращает user_id.
    Хранит только SHA-256 хеш токена — сырой токен в БД не хранится.
    Продлевает сессию при каждом успешном обращении (скользящее окно 12 часов).
    """
    token_hash = hashlib.sha256(token.encode()).digest()

    with Session(engine) as session:
        s = session.query(models.SessionModel).filter_by(hashed_token=token_hash).first()

        if not s:
            return None

        if s.expires_at < utcnow():
            session.delete(s)
            session.commit()
            return None

        s.expires_at = utcnow() + timedelta(hours=12)
        session.commit()

        return s.user_id


def get_user_chats(user_id: int) -> list[str]:
    """Возвращает список имён чатов, в которых состоит пользователь."""
    with Session(engine) as session:
        memberships = (
            session.query(models.ChatMembership)
            .filter_by(user_id=user_id)
            .all()
        )
        return [m.chat.name for m in memberships]


def is_user_online(user_id: int) -> bool:
    """Проверяет, есть ли у пользователя хотя бы одно активное соединение."""
    return bool(user_sids.get(user_id))


def emit_to_user(user_id: int, event: str, data: dict) -> None:
    """Отправляет событие всем активным соединениям конкретного пользователя."""
    for sid in user_sids.get(user_id, set()):
        socketio.emit(event, data, to=sid)


@event.listens_for(engine, "connect")
def enable_foreign_keys(dbapi_connection, _):
    """Включаем поддержку внешних ключей в SQLite (по умолчанию отключена)."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.route("/api")
def check():
    return jsonify({"status": "ok"})


@app.route("/api/register", methods=["POST"])
def register():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "Тело запроса отсутствует"})

    username = data.get("username")
    password = data.get("password")
    public_key_b64 = data.get("public_key")

    if not username or not password or not public_key_b64:
        return jsonify({"status": "error", "error": "Не переданы обязательные поля"})

    if not USERNAME_REGEX.fullmatch(username):
        return jsonify({"status": "error", "error": "Недопустимое имя пользователя"})

    try:
        public_key = base64.b64decode(public_key_b64)
        if len(public_key) != 32:
            raise ValueError("Неверная длина ключа")
    except Exception:
        return jsonify({"status": "error", "error": "Некорректный публичный ключ"})

    password_hash = ph.hash(password)

    with Session(engine) as session:
        user = models.User(
            username=username,
            password_hash=password_hash,
            public_key=public_key,
        )
        session.add(user)
        try:
            session.commit()
        except IntegrityError:
            session.rollback()
            return jsonify({"status": "error", "error": "Пользователь с таким именем уже существует"})

    return jsonify({"status": "ok"})


@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "Тело запроса отсутствует"})

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "error": "Не переданы обязательные поля"})

    with Session(engine) as session:
        user = session.query(models.User).filter_by(username=username).first()

        # Одинаковое сообщение для «нет пользователя» и «неверный пароль»,
        # чтобы не раскрывать факт существования аккаунта
        if not user:
            return jsonify({"status": "error", "error": "Неверные учётные данные"})

        try:
            ph.verify(user.password_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return jsonify({"status": "error", "error": "Неверные учётные данные"})

        # Перехеширование при устаревших параметрах Argon2
        if ph.check_needs_rehash(user.password_hash):
            user.password_hash = ph.hash(password)

        token = secrets.token_hex(32)
        hashed_token = hashlib.sha256(token.encode()).digest()

        session_obj = models.SessionModel(
            hashed_token=hashed_token,
            user_id=user.id,
            expires_at=utcnow() + timedelta(hours=12),
        )
        session.add(session_obj)
        session.commit()

    return jsonify({"status": "ok", "token": token})


@app.route("/api/get_user", methods=["GET"])
def get_user():
    token = get_token_from_request()
    if not token:
        return jsonify({"status": "error", "error": "Требуется авторизация"}), 401

    username = request.args.get("username")
    if not username:
        return jsonify({"status": "error", "error": "Не передан username"})

    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"status": "error", "error": "Сессия недействительна"}), 401

    with Session(engine) as session:
        db_user = session.query(models.User).filter_by(username=username).first()

        if not db_user:
            return jsonify({"status": "error", "error": "Пользователь не найден"}), 404

        return jsonify({
            "status": "ok",
            "user": {
                "id": db_user.id,
                "username": db_user.username,
                "last_online": db_user.last_online.isoformat(),
                "public_key": base64.b64encode(db_user.public_key).decode(),
                # Онлайн-статус по наличию активных WebSocket-соединений
                "online": is_user_online(db_user.id),
            }
        })


@app.route("/api/create_chat", methods=["POST"])
def create_chat():
    token = get_token_from_request()
    if not token:
        return jsonify({"status": "error", "error": "Требуется авторизация"}), 401

    data = request.json
    if not data:
        return jsonify({"status": "error", "error": "Тело запроса отсутствует"})

    chat_name = data.get("chat_name")
    display_name = data.get("display_name")
    keys = data.get("keys")

    if not chat_name or not display_name or not keys:
        return jsonify({"status": "error", "error": "Не переданы обязательные поля"})

    if not isinstance(keys, dict) or not keys:
        return jsonify({"status": "error", "error": "Некорректный формат ключей"})

    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"status": "error", "error": "Сессия недействительна"}), 401

    usernames = list(keys.keys())

    with Session(engine) as session:
        db_user = session.query(models.User).filter_by(id=user_id).first()

        if not db_user:
            return jsonify({"status": "error", "error": "Пользователь не найден"}), 404

        if db_user.username not in keys:
            return jsonify({"status": "error", "error": "Создатель чата должен быть участником"})

        db_users = session.query(models.User).filter(
            models.User.username.in_(usernames)
        ).all()

        found_names = {u.username for u in db_users}
        missing = set(usernames) - found_names
        if missing:
            return jsonify({
                "status": "error",
                "error": f"Пользователи не найдены: {', '.join(missing)}"
            }), 404

        chat = models.Chat(
            name=chat_name,
            display_name=display_name,
            creator_id=user_id,
        )
        session.add(chat)
        try:
            session.flush()
        except IntegrityError:
            session.rollback()
            return jsonify({"status": "error", "error": "Чат с таким именем уже существует"})

        for u in db_users:
            enc_b64 = keys.get(u.username)
            if not enc_b64:
                session.rollback()
                return jsonify({"status": "error", "error": f"Отсутствует ключ для {u.username}"})

            try:
                enc = base64.b64decode(enc_b64)
            except Exception:
                session.rollback()
                return jsonify({"status": "error", "error": "Некорректный формат ключа"})

            session.add(models.ChatMembership(
                user_id=u.id,
                chat_id=chat.id,
                encrypted_group_key=enc,
            ))

        chat_id = chat.id
        member_usernames = [u.username for u in db_users]
        session.commit()

    # Уведомляем всех онлайн-участников нового чата через WebSocket
    for username in member_usernames:
        with Session(engine) as session:
            u = session.query(models.User).filter_by(username=username).first()
            if u and is_user_online(u.id):
                emit_to_user(u.id, "chat_created", {
                    "chat_name": chat_name,
                    "display_name": display_name,
                    "members": member_usernames,
                    # Зашифрованный ключ чата для конкретного участника
                    "encrypted_group_key": keys[username],
                })
                # Добавляем в SocketIO-комнату всех активных подключённых участников
                for sid in user_sids.get(u.id, set()):
                    socketio.server.enter_room(sid, chat_name)

    return jsonify({"status": "ok", "chat_id": chat_id})


@app.route("/api/get_chats", methods=["GET"])
def get_chats():
    token = get_token_from_request()
    if not token:
        return jsonify({"status": "error", "error": "Требуется авторизация"}), 401

    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"status": "error", "error": "Сессия недействительна"}), 401

    with Session(engine) as session:
        memberships = (
            session.query(models.ChatMembership)
            .filter_by(user_id=user_id)
            .all()
        )

        chats = []
        for membership in memberships:
            chat = membership.chat

            unread_count = (
                session.query(models.Message)
                .filter(
                    models.Message.chat_id == chat.id,
                    ~models.Message.reads.any(models.MessageRead.user_id == user_id),
                )
                .count()
            )

            chats.append({
                "server_id": chat.id,
                "name": chat.name,
                "display_name": chat.display_name,
                "members": [m.user.username for m in chat.members],
                "encrypted_group_key": base64.b64encode(membership.encrypted_group_key).decode(),
                "new_messages": unread_count,
            })

    return jsonify({"status": "ok", "chats": chats})


def cleanup_messages(chat_id: int, member_count: int) -> None:
    """
    Удаляет сообщения, которые прочитали все участники чата.
    Работает только с сообщениями конкретного чата, а не со всей таблицей.
    """
    with Session(engine) as session:
        messages = (
            session.query(models.Message)
            .filter_by(chat_id=chat_id)
            .all()
        )
        for msg in messages:
            if len(msg.reads) >= member_count:
                session.delete(msg)
        session.commit()


@app.route("/api/get_messages", methods=["GET"])
def get_messages():
    token = get_token_from_request()
    if not token:
        return jsonify({"status": "error", "error": "Требуется авторизация"}), 401

    chat_name = request.args.get("chat_name")
    if not chat_name:
        return jsonify({"status": "error", "error": "Не передан chat_name"})

    user_id = get_user_from_token(token)
    if not user_id:
        return jsonify({"status": "error", "error": "Сессия недействительна"}), 401

    with Session(engine) as session:
        chat = session.query(models.Chat).filter_by(name=chat_name).first()
        if not chat:
            return jsonify({"status": "error", "error": "Чат не найден"}), 404

        membership = session.query(models.ChatMembership).filter_by(
            user_id=user_id, chat_id=chat.id
        ).first()
        if not membership:
            return jsonify({"status": "error", "error": "Вы не являетесь участником этого чата"}), 403

        member_count = session.query(models.ChatMembership).filter_by(chat_id=chat.id).count()

        messages = []
        newly_read_ids = []

        for message in chat.pending_messages:
            already_read = session.query(models.MessageRead).filter_by(
                user_id=user_id, message_id=message.id
            ).first()
            if already_read:
                continue

            session.add(models.MessageRead(message_id=message.id, user_id=user_id))
            newly_read_ids.append(message.id)

            messages.append({
                "id": message.id,
                "user": message.user.username,
                "created_at": message.created_at.isoformat(),
                "reads": [r.user.username for r in message.reads],
                "content": base64.b64encode(message.content).decode(),
            })

        session.commit()

        # Получаем username текущего пользователя для квитанции о прочтении
        current_user = session.query(models.User).filter_by(id=user_id).first()
        current_username = current_user.username if current_user else ""

    # Уведомляем остальных участников чата о прочтении через WebSocket
    if newly_read_ids:
        socketio.emit(
            "read_receipt",
            {
                "chat_name": chat_name,
                "message_ids": newly_read_ids,
                "reader": current_username,
            },
            room=chat_name,
            skip_sid=list(user_sids.get(user_id, set())),
        )

    cleanup_messages(chat.id, member_count)

    return jsonify({"status": "ok", "messages": messages})


# ---------------------------------------------------------------------------
# SocketIO — подключение и отключение
# ---------------------------------------------------------------------------

@socketio.on("connect")
def on_connect(auth):
    """
    Проверяем токен при подключении.
    При успехе — добавляем в индексы и подписываем на комнаты всех чатов.
    """
    if not auth or not isinstance(auth, dict):
        socketio_disconnect()
        return

    token = auth.get("token")
    if not token:
        socketio_disconnect()
        return

    user_id = get_user_from_token(token)
    if not user_id:
        socketio_disconnect()
        return

    sid = request.sid

    # Регистрируем соединение в обоих индексах
    connected_users[sid] = user_id
    user_sids.setdefault(user_id, set()).add(sid)

    # Подписываем соединение на SocketIO-комнату каждого чата пользователя.
    # Комнаты используются для групповой рассылки: emit(..., room=chat_name).
    chat_names = get_user_chats(user_id)
    for chat_name in chat_names:
        join_room(chat_name)

    # Обновляем last_online и уведомляем контакты о выходе онлайн
    with Session(engine) as session:
        user = session.query(models.User).filter_by(id=user_id).first()
        if user:
            username = user.username
            user.last_online = utcnow()
            session.commit()

    for chat_name in chat_names:
        emit(
            "user_online",
            {"username": username, "chat_name": chat_name},
            room=chat_name,
            skip_sid=sid,  # не отправляем себе
        )


@socketio.on("disconnect")
def on_disconnect():
    """
    При отключении убираем sid из индексов.
    Если это было последнее соединение пользователя — уведомляем контакты.
    """
    sid = request.sid
    user_id = connected_users.pop(sid, None)

    if user_id is None:
        return

    sids = user_sids.get(user_id, set())
    sids.discard(sid)

    if not sids:
        # Последнее соединение закрыто — пользователь ушёл офлайн
        user_sids.pop(user_id, None)

        with Session(engine) as session:
            user = session.query(models.User).filter_by(id=user_id).first()
            if user:
                username = user.username
                user.last_online = utcnow()
                session.commit()

        chat_names = get_user_chats(user_id)
        for chat_name in chat_names:
            emit(
                "user_offline",
                {
                    "username": username,
                    "chat_name": chat_name,
                    "last_online": utcnow().isoformat(),
                },
                room=chat_name,
            )


# ---------------------------------------------------------------------------
# SocketIO — обмен сообщениями
# ---------------------------------------------------------------------------

@socketio.on("send_message")
def on_send_message(data):
    """
    Клиент отправляет зашифрованное сообщение в чат.

    Ожидаемые поля data:
        chat_name  (str)  — имя чата
        content    (str)  — зашифрованное содержимое, base64

    Что происходит:
        1. Проверяем авторизацию и членство в чате.
        2. Сохраняем сообщение в БД.
        3. Рассылаем new_message всем в комнате (включая отправителя —
           это подтверждает доставку и синхронизирует несколько устройств).
    """
    sid = request.sid
    user_id = connected_users.get(sid)
    if not user_id:
        socketio_disconnect()
        return

    if not isinstance(data, dict):
        emit("error", {"error": "Некорректный формат данных"})
        return

    chat_name = data.get("chat_name")
    content_b64 = data.get("content")

    if not chat_name or not content_b64:
        emit("error", {"error": "Не переданы обязательные поля: chat_name, content"})
        return

    try:
        content_bytes = base64.b64decode(content_b64)
    except Exception:
        emit("error", {"error": "Некорректный base64 в поле content"})
        return

    with Session(engine) as session:
        chat = session.query(models.Chat).filter_by(name=chat_name).first()
        if not chat:
            emit("error", {"error": "Чат не найден"})
            return

        membership = session.query(models.ChatMembership).filter_by(
            user_id=user_id, chat_id=chat.id
        ).first()
        if not membership:
            emit("error", {"error": "Вы не являетесь участником этого чата"})
            return

        user = session.query(models.User).filter_by(id=user_id).first()
        username = user.username

        msg = models.Message(
            user_id=user_id,
            chat_id=chat.id,
            content=content_bytes,
        )
        session.add(msg)
        session.flush()  # получаем msg.id до commit

        msg_id = msg.id
        created_at = msg.created_at.isoformat()
        session.commit()

    # Рассылаем сообщение всем участникам комнаты (онлайн)
    socketio.emit(
        "new_message",
        {
            "id": msg_id,
            "chat_name": chat_name,
            "user": username,
            "content": content_b64,  # передаём как пришло, расшифровка на клиенте
            "created_at": created_at,
        },
        room=chat_name,
    )


@socketio.on("typing")
def on_typing(data):
    """
    Клиент сигнализирует, что пользователь печатает.

    Ожидаемые поля data:
        chat_name (str)  — имя чата
        is_typing (bool) — True — начал печатать, False — перестал

    Событие пересылается всем в комнате, кроме отправителя.
    """
    sid = request.sid
    user_id = connected_users.get(sid)
    if not user_id:
        return

    if not isinstance(data, dict):
        return

    chat_name = data.get("chat_name")
    is_typing = data.get("is_typing", False)

    if not chat_name:
        return

    with Session(engine) as session:
        # Проверяем членство в чате
        chat = session.query(models.Chat).filter_by(name=chat_name).first()
        if not chat:
            return
        membership = session.query(models.ChatMembership).filter_by(
            user_id=user_id, chat_id=chat.id
        ).first()
        if not membership:
            return

        user = session.query(models.User).filter_by(id=user_id).first()
        username = user.username if user else ""

    emit(
        "typing",
        {
            "chat_name": chat_name,
            "username": username,
            "is_typing": bool(is_typing),
        },
        room=chat_name,
        skip_sid=sid,  # не отправляем себе
    )


@socketio.on("mark_read")
def on_mark_read(data):
    """
    Клиент подтверждает прочтение конкретных сообщений.

    Ожидаемые поля data:
        chat_name   (str)       — имя чата
        message_ids (list[int]) — список id прочитанных сообщений

    Сервер сохраняет отметки в БД и рассылает read_receipt остальным участникам.
    Удаляет сообщения, прочитанные всеми.
    """
    sid = request.sid
    user_id = connected_users.get(sid)
    if not user_id:
        return

    if not isinstance(data, dict):
        return

    chat_name = data.get("chat_name")
    message_ids = data.get("message_ids", [])

    if not chat_name or not isinstance(message_ids, list) or not message_ids:
        return

    with Session(engine) as session:
        chat = session.query(models.Chat).filter_by(name=chat_name).first()
        if not chat:
            return

        membership = session.query(models.ChatMembership).filter_by(
            user_id=user_id, chat_id=chat.id
        ).first()
        if not membership:
            return

        user = session.query(models.User).filter_by(id=user_id).first()
        username = user.username if user else ""
        member_count = session.query(models.ChatMembership).filter_by(chat_id=chat.id).count()

        confirmed_ids = []
        for msg_id in message_ids:
            msg = session.query(models.Message).filter_by(id=msg_id, chat_id=chat.id).first()
            if not msg:
                continue
            already = session.query(models.MessageRead).filter_by(
                user_id=user_id, message_id=msg_id
            ).first()
            if already:
                continue
            session.add(models.MessageRead(message_id=msg_id, user_id=user_id))
            confirmed_ids.append(msg_id)

        session.commit()

    if confirmed_ids:
        # Уведомляем остальных участников чата о прочтении
        emit(
            "read_receipt",
            {
                "chat_name": chat_name,
                "message_ids": confirmed_ids,
                "reader": username,
            },
            room=chat_name,
            skip_sid=sid,
        )
        cleanup_messages(chat.id, member_count)


if __name__ == "__main__":
    models.Base.metadata.create_all(engine)
    socketio.run(app, host="127.0.0.1", port=5000)
