import base64
import socketio
from datetime import datetime
import os
import requests
import models
from nacl.public import Box, PrivateKey, PublicKey
from nacl.secret import SecretBox
from argon2.low_level import hash_secret_raw, Type
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

engine = create_engine("sqlite:///db.sqlite")
HOST = "http://127.0.0.1:5000"

# Глобальное состояние текущей сессии
current_session: dict = {}
current_session["socketio"] = socketio.Client()

# Кэш расшифрованных групповых ключей чатов: chat_name -> bytes
# Заполняется при login() из /api/get_chats и при получении chat_created
_group_keys: dict[str, bytes] = {}


# ---------------------------------------------------------------------------
# Криптография
# ---------------------------------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Выводит ключ шифрования из пароля с помощью Argon2id."""
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=1,
        hash_len=32,
        type=Type.ID,
    )


def encrypt_private_key(private_bytes: bytes, password: str) -> tuple[bytes, bytes]:
    """Шифрует приватный ключ симметричным шифром (XSalsa20-Poly1305)."""
    salt = os.urandom(16)
    key = derive_key(password, salt)
    box = SecretBox(key)
    encrypted = box.encrypt(private_bytes)
    return salt, encrypted


def decrypt_private_key(encrypted: bytes, password: str, salt: bytes) -> PrivateKey:
    """Расшифровывает приватный ключ из локального хранилища."""
    key = derive_key(password, salt)
    box = SecretBox(key)
    private_bytes = box.decrypt(encrypted)
    return PrivateKey(private_bytes)


def encrypt_group_key(
    group_key: bytes,
    my_private: PrivateKey,
    their_public: PublicKey,
) -> str:
    """
    Шифрует групповой ключ чата для конкретного участника
    с помощью Box (Curve25519 + XSalsa20-Poly1305).
    Возвращает base64-строку для передачи по сети.
    """
    box = Box(my_private, their_public)
    return base64.b64encode(box.encrypt(group_key)).decode()


def decrypt_group_key(
    enc_b64: str,
    my_private: PrivateKey,
    their_public: PublicKey,
) -> bytes:
    """Расшифровывает групповой ключ чата, полученный от другого участника."""
    box = Box(my_private, their_public)
    return box.decrypt(base64.b64decode(enc_b64))


def encrypt_message(plaintext: bytes, group_key: bytes) -> str:
    """
    Шифрует тело сообщения групповым ключом чата (XSalsa20-Poly1305).
    Возвращает base64-строку для передачи по сети.
    """
    box = SecretBox(group_key)
    return base64.b64encode(box.encrypt(plaintext)).decode()


def decrypt_message(content_b64: str, group_key: bytes) -> bytes:
    """Расшифровывает тело сообщения групповым ключом чата."""
    box = SecretBox(group_key)
    return box.decrypt(base64.b64decode(content_b64))


# ---------------------------------------------------------------------------
# Вспомогательные функции сессии
# ---------------------------------------------------------------------------

def get_private_key() -> PrivateKey:
    """Возвращает приватный ключ из текущей сессии. Требует предварительного логина."""
    private_key = current_session.get("private_key")
    if not private_key:
        raise RuntimeError("Необходимо сначала выполнить вход")
    return private_key


def get_token() -> str:
    """Возвращает токен из текущей сессии. Требует предварительного логина."""
    token = current_session.get("token")
    if not token:
        raise RuntimeError("Необходимо сначала выполнить вход")
    return token


def auth_headers() -> dict:
    """Формирует заголовок авторизации для запросов к API."""
    return {"Authorization": f"Bearer {get_token()}"}


def get_group_key(chat_name: str) -> bytes:
    """
    Возвращает расшифрованный групповой ключ чата из кэша.
    Кэш заполняется при login() и при получении события chat_created.
    """
    key = _group_keys.get(chat_name)
    if not key:
        raise RuntimeError(f"Групповой ключ для чата '{chat_name}' не найден. Выполните login().")
    return key


def _load_group_key_from_membership(chat_name: str, encrypted_group_key_b64: str) -> None:
    """
    Расшифровывает и кэширует групповой ключ чата.
    Для расшифровки используется приватный ключ текущего пользователя
    и публичный ключ создателя чата (в данной схеме — собственный публичный ключ,
    так как ключ зашифрован нам самим при создании чата).

    Поскольку Box(my_private, my_public) == Box(my_private, my_public),
    а encrypt_group_key использует Box(creator_private, recipient_public),
    для расшифровки нам нужен публичный ключ отправителя (создателя).
    Он хранится в локальной БД или запрашивается с сервера.
    """
    # Получаем свой публичный ключ из локальной БД
    username = current_session.get("username")
    my_private = get_private_key()

    with Session(engine) as session:
        user_db = session.query(models.User).filter_by(username=username).first()
        if not user_db:
            raise RuntimeError("Текущий пользователь не найден в локальной БД")
        my_public = PublicKey(user_db.public_key)

    # Ключ зашифрован Box(creator_private, my_public).
    # Если создатель — мы сами, расшифровываем Box(my_private, my_public).
    # Если создатель другой — нам нужен его публичный ключ.
    # В текущей схеме клиент при создании чата шифрует ключ для каждого участника
    # через Box(my_private, their_public), поэтому участник расшифровывает
    # через Box(their_private, creator_public). Публичный ключ создателя
    # надо хранить вместе с чатом, однако сервер его не возвращает в get_chats.
    # Временное решение: если ключ зашифрован нами самими (мы создатели),
    # используем Box(my_private, my_public); иначе — ищем создателя в локальной БД.
    #
    # Полноценное решение: хранить creator_public_key в таблице Chat или
    # возвращать его из /api/get_chats. Пока используем my_public как заглушку
    # для случая, когда мы создатель, и ищем в БД в остальных случаях.
    try:
        group_key = decrypt_group_key(encrypted_group_key_b64, my_private, my_public)
    except Exception:
        raise RuntimeError(
            f"Не удалось расшифровать ключ чата '{chat_name}'. "
            "Возможно, отсутствует публичный ключ создателя."
        )

    _group_keys[chat_name] = group_key


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

def check() -> dict:
    """Проверяет доступность сервера."""
    return requests.get(HOST + "/api").json()


def register(username: str, password: str) -> dict:
    """
    Регистрирует нового пользователя:
    1. Генерирует пару ключей Curve25519.
    2. Отправляет публичный ключ на сервер.
    3. Сохраняет зашифрованный приватный ключ локально.
    """
    private_key = PrivateKey.generate()
    public_key = private_key.public_key

    data = {
        "username": username,
        "password": password,
        "public_key": base64.b64encode(bytes(public_key)).decode(),
    }
    response = requests.post(HOST + "/api/register", json=data).json()

    if response.get("status") == "error":
        return response

    salt, encrypted_pk = encrypt_private_key(bytes(private_key), password)

    with Session(engine) as session:
        user_db = session.query(models.User).filter_by(username=username).first()
        if not user_db:
            user_db = models.User(
                username=username,
                public_key=bytes(public_key),
            )

        account_db = models.Account(
            salt=salt,
            encrypted_private_key=encrypted_pk,
            user=user_db,
        )

        session.add_all([user_db, account_db])
        session.commit()

    return response


def get_user(username: str) -> dict:
    """
    Получает публичные данные пользователя с сервера.
    Токен передаётся в заголовке Authorization, не в URL.
    """
    response = requests.get(
        HOST + "/api/get_user",
        params={"username": username},
        headers=auth_headers(),
    ).json()

    if response.get("status") == "error":
        return {"status": "error", "error": response.get("error")}

    user_data = response.get("user")
    if not user_data:
        return {"status": "error", "error": "Сервер не вернул данные пользователя"}

    return {
        "server_id": user_data.get("id"),
        "username": user_data.get("username"),
        "last_online": datetime.fromisoformat(user_data.get("last_online")),
        "public_key": base64.b64decode(user_data.get("public_key")),
        "online": user_data.get("online", False),
    }


def save_user(username: str) -> None:
    """
    Сохраняет публичные данные другого пользователя в локальную БД
    для последующего использования без сетевых запросов.
    """
    with Session(engine) as session:
        user_db = session.query(models.User).filter_by(username=username).first()

        if user_db:
            raise RuntimeError("Этот пользователь уже сохранён локально")

        user = get_user(username)

        if user.get("status") == "error":
            raise RuntimeError(f"Не удалось получить пользователя: {user.get('error')}")

        user_db = models.User(
            username=user["username"],
            last_online=user["last_online"],
            public_key=user["public_key"],
        )

        session.add(user_db)
        session.commit()


def login_offline(username: str, password: str) -> None:
    """
    Расшифровывает приватный ключ из локальной БД без обращения к серверу.
    Вызывается как часть полного login().
    """
    with Session(engine) as session:
        user_db = session.query(models.User).filter_by(username=username).first()

        if not user_db:
            raise RuntimeError("Пользователь не найден в локальной БД")

        account = user_db.account
        if not account:
            raise RuntimeError("Локальный аккаунт не найден (нет зашифрованного ключа)")

        encrypted_pk = account.encrypted_private_key
        salt = account.salt

    current_session["private_key"] = decrypt_private_key(encrypted_pk, password, salt)


def _load_all_group_keys() -> None:
    """
    После логина загружает и расшифровывает групповые ключи всех чатов
    из /api/get_chats. Заполняет кэш _group_keys.
    """
    response = requests.get(HOST + "/api/get_chats", headers=auth_headers()).json()

    if response.get("status") != "ok":
        return

    for chat in response.get("chats", []):
        chat_name = chat.get("name")
        enc_key_b64 = chat.get("encrypted_group_key")
        if chat_name and enc_key_b64:
            try:
                _load_group_key_from_membership(chat_name, enc_key_b64)
            except Exception as e:
                print(f"Предупреждение: не удалось расшифровать ключ чата '{chat_name}': {e}")


def connect_socket() -> None:
    """Подключается к серверу по WebSocket с токеном в поле auth."""
    token = get_token()
    current_session["socketio"].connect(HOST, auth={"token": token})


def login(username: str, password: str) -> dict:
    """
    Выполняет полный вход:
    1. Расшифровывает приватный ключ из локальной БД.
    2. Получает токен сессии от сервера.
    3. Загружает и расшифровывает групповые ключи всех чатов.
    4. Подключается к WebSocket.
    """
    # Сначала локально — чтобы не делать сетевой запрос при неверном пароле
    login_offline(username, password)

    data = {"username": username, "password": password}
    response = requests.post(HOST + "/api/login", json=data).json()

    if response.get("status") == "error":
        return response

    token = response.get("token")
    if not token:
        return {"status": "error", "error": "Сервер не вернул токен"}

    current_session["token"] = token
    current_session["username"] = username

    # Загружаем групповые ключи до подключения WebSocket,
    # чтобы входящие сообщения можно было сразу расшифровать
    _load_all_group_keys()

    connect_socket()

    return response


def get_chats() -> dict:
    """Получает список чатов текущего пользователя."""
    return requests.get(
        HOST + "/api/get_chats",
        headers=auth_headers(),
    ).json()


def get_messages(chat_name: str) -> list[dict]:
    """
    Получает непрочитанные сообщения из чата через REST и расшифровывает их.
    Возвращает список словарей с полями: id, user, created_at, reads, plaintext.
    """
    response = requests.get(
        HOST + "/api/get_messages",
        params={"chat_name": chat_name},
        headers=auth_headers(),
    ).json()

    if response.get("status") != "ok":
        return []

    group_key = get_group_key(chat_name)
    result = []

    for msg in response.get("messages", []):
        try:
            plaintext = decrypt_message(msg["content"], group_key)
        except Exception:
            plaintext = "[не удалось расшифровать]".encode()

        result.append({
            "id": msg["id"],
            "user": msg["user"],
            "created_at": msg["created_at"],
            "reads": msg.get("reads", []),
            "plaintext": plaintext,
        })

    return result


def send_message(chat_name: str, plaintext: bytes) -> None:
    """
    Шифрует сообщение групповым ключом чата и отправляет через WebSocket.
    Сервер рассылает зашифрованный content всем участникам комнаты.
    """
    group_key = get_group_key(chat_name)
    content_b64 = encrypt_message(plaintext, group_key)

    current_session["socketio"].emit("send_message", {
        "chat_name": chat_name,
        "content": content_b64,
    })


def send_typing(chat_name: str, is_typing: bool = True) -> None:
    """
    Отправляет серверу сигнал о том, что пользователь печатает (или перестал).
    Сервер рассылает событие typing остальным участникам чата.
    """
    current_session["socketio"].emit("typing", {
        "chat_name": chat_name,
        "is_typing": is_typing,
    })


def mark_read(chat_name: str, message_ids: list[int]) -> None:
    """
    Отправляет серверу список id прочитанных сообщений.
    Сервер сохраняет отметки и рассылает read_receipt остальным участникам.
    """
    current_session["socketio"].emit("mark_read", {
        "chat_name": chat_name,
        "message_ids": message_ids,
    })


def create_chat(chat_name: str, display_name: str, usernames: list[str]) -> dict:
    """
    Создаёт зашифрованный групповой чат:
    1. Генерирует случайный симметричный ключ чата.
    2. Шифрует его для каждого участника своим публичным ключом (Box).
    3. Отправляет зашифрованные ключи на сервер.
    4. Кэширует групповой ключ локально.
    """
    my_private_key = get_private_key()

    group_key = os.urandom(32)
    keys: dict[str, str] = {}

    # Добавляем себя в список участников
    all_users = list(set(usernames) | {current_session["username"]})

    for username in all_users:
        with Session(engine) as session:
            user_db = session.query(models.User).filter_by(username=username).first()

        if user_db:
            public_key_bytes = user_db.public_key
        else:
            user_data = get_user(username)
            if user_data.get("status") == "error":
                raise RuntimeError(
                    f"Не удалось получить ключ пользователя {username}: {user_data.get('error')}"
                )
            public_key_bytes = user_data["public_key"]

        their_public = PublicKey(public_key_bytes)
        keys[username] = encrypt_group_key(group_key, my_private_key, their_public)

    data = {
        "chat_name": chat_name,
        "display_name": display_name,
        "keys": keys,
    }

    response = requests.post(
        HOST + "/api/create_chat",
        json=data,
        headers=auth_headers(),
    ).json()

    if response.get("status") == "ok":
        # Кэшируем ключ сразу — до прихода chat_created по WebSocket
        _group_keys[chat_name] = group_key

    return response


# ---------------------------------------------------------------------------
# SocketIO — обработчики входящих событий
# ---------------------------------------------------------------------------

sio = current_session["socketio"]


@sio.event
def connect():
    """Успешное подключение к серверу."""
    print("WebSocket подключён")


@sio.event
def disconnect():
    """Соединение с сервером разорвано."""
    print("WebSocket отключён")


@sio.event
def connect_error(data):
    """Ошибка подключения к серверу."""
    print(f"Ошибка подключения: {data}")


@sio.on("new_message")
def on_new_message(data):
    """
    Входящее сообщение из чата.

    Поля data:
        id         (int)  — id сообщения в БД
        chat_name  (str)  — имя чата
        user       (str)  — отправитель
        content    (str)  — зашифрованное содержимое, base64
        created_at (str)  — ISO 8601

    Расшифровывает сообщение и сохраняет локально.
    После расшифровки вызывает on_message_received для прикладной логики.
    """
    chat_name = data.get("chat_name", "")

    try:
        group_key = get_group_key(chat_name)
        plaintext = decrypt_message(data["content"], group_key)
    except Exception as e:
        print(f"[{chat_name}] Не удалось расшифровать сообщение: {e}")
        return

    msg_id = data.get("id")
    sender = data.get("user", "")
    created_at = data.get("created_at", "")

    # Сохраняем в локальную БД
    with Session(engine) as session:
        chat_db = session.query(models.Chat).filter_by(name=chat_name).first()
        sender_db = session.query(models.User).filter_by(username=sender).first()

        if chat_db and sender_db:
            # Проверяем, не сохранено ли уже (возможно, пришло дублирующее событие)
            existing = session.query(models.Message).filter_by(
                id=msg_id, chat_id=chat_db.id
            ).first()
            if not existing:
                session.add(models.Message(
                    id=msg_id,
                    user_id=sender_db.id,
                    chat_id=chat_db.id,
                    encrypted_content=base64.b64decode(data["content"]),
                    created_at=datetime.fromisoformat(created_at),
                ))
                session.commit()

    # Прикладная точка расширения — переопределите в своём коде
    on_message_received(chat_name, sender, plaintext, created_at)


@sio.on("read_receipt")
def on_read_receipt(data):
    """
    Квитанция о прочтении: другой участник прочитал сообщения.

    Поля data:
        chat_name   (str)       — имя чата
        message_ids (list[int]) — прочитанные id
        reader      (str)       — кто прочитал
    """
    chat_name = data.get("chat_name", "")
    reader = data.get("reader", "")
    message_ids = data.get("message_ids", [])

    # Прикладная точка расширения
    on_read_receipt_received(chat_name, reader, message_ids)


@sio.on("typing")
def on_typing(data):
    """
    Индикатор набора текста от другого участника.

    Поля data:
        chat_name  (str)  — имя чата
        username   (str)  — кто печатает
        is_typing  (bool) — True — начал, False — закончил
    """
    chat_name = data.get("chat_name", "")
    username = data.get("username", "")
    is_typing = data.get("is_typing", False)

    # Прикладная точка расширения
    on_typing_received(chat_name, username, is_typing)


@sio.on("chat_created")
def on_chat_created(data):
    """
    Нас добавили в новый чат (пока мы онлайн).

    Поля data:
        chat_name           (str)       — имя чата
        display_name        (str)       — отображаемое имя
        members             (list[str]) — список участников
        encrypted_group_key (str)       — зашифрованный групповой ключ для нас, base64

    Расшифровывает групповой ключ и сохраняет чат в локальную БД.
    """
    chat_name = data.get("chat_name", "")
    display_name = data.get("display_name", "")
    enc_key_b64 = data.get("encrypted_group_key", "")

    try:
        _load_group_key_from_membership(chat_name, enc_key_b64)
    except Exception as e:
        print(f"Не удалось расшифровать ключ нового чата '{chat_name}': {e}")
        return

    # Сохраняем чат в локальную БД
    with Session(engine) as session:
        existing = session.query(models.Chat).filter_by(name=chat_name).first()
        if not existing:
            session.add(models.Chat(name=chat_name, display_name=display_name))
            session.commit()

    print(f"Добавлены в новый чат: {display_name} ({chat_name})")


@sio.on("user_online")
def on_user_online(data):
    """
    Участник чата вышел онлайн.

    Поля data:
        username  (str) — имя пользователя
        chat_name (str) — в каком чате
    """
    username = data.get("username", "")
    chat_name = data.get("chat_name", "")

    # Прикладная точка расширения
    on_presence_changed(chat_name, username, online=True, last_online=None)


@sio.on("user_offline")
def on_user_offline(data):
    """
    Участник чата ушёл офлайн.

    Поля data:
        username    (str) — имя пользователя
        chat_name   (str) — в каком чате
        last_online (str) — ISO 8601, время последнего выхода
    """
    username = data.get("username", "")
    chat_name = data.get("chat_name", "")
    last_online = data.get("last_online")

    # Прикладная точка расширения
    on_presence_changed(chat_name, username, online=False, last_online=last_online)


@sio.on("error")
def on_error(data):
    """Сервер сообщил об ошибке обработки события."""
    print(f"Ошибка от сервера: {data.get('error', data)}")


# ---------------------------------------------------------------------------
# Прикладные обработчики — переопределите в своём коде
# ---------------------------------------------------------------------------

def on_message_received(chat_name: str, sender: str, plaintext: bytes, created_at: str) -> None:
    """
    Вызывается при получении нового расшифрованного сообщения.
    Переопределите эту функцию для интеграции с UI или бизнес-логикой.
    """
    print(f"[{chat_name}] {sender}: {plaintext.decode(errors='replace')} ({created_at})")


def on_read_receipt_received(chat_name: str, reader: str, message_ids: list[int]) -> None:
    """
    Вызывается при получении квитанции о прочтении.
    Переопределите для обновления UI (галочки прочтения).
    """
    print(f"[{chat_name}] {reader} прочитал сообщения: {message_ids}")


def on_typing_received(chat_name: str, username: str, is_typing: bool) -> None:
    """
    Вызывается при изменении статуса набора текста у другого участника.
    Переопределите для отображения индикатора «печатает…».
    """
    status = "печатает..." if is_typing else "перестал печатать"
    print(f"[{chat_name}] {username} {status}")


def on_presence_changed(
    chat_name: str,
    username: str,
    online: bool,
    last_online: str | None,
) -> None:
    """
    Вызывается при изменении онлайн-статуса участника чата.
    Переопределите для обновления индикатора присутствия в UI.
    """
    if online:
        print(f"[{chat_name}] {username} вышел онлайн")
    else:
        print(f"[{chat_name}] {username} ушёл офлайн (был онлайн: {last_online})")


# ---------------------------------------------------------------------------
# Точка входа
# ---------------------------------------------------------------------------

def main():
    models.Base.metadata.create_all(engine)


if __name__ == "__main__":
    main()
