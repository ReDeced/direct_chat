from datetime import datetime, timezone
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Текущее время UTC (aware). datetime.utcnow() устарел в Python 3.12."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    ...


class Account(Base):
    """
    Локальный аккаунт пользователя.
    Хранит зашифрованный приватный ключ и соль для его расшифровки.
    Существует только для пользователей, зарегистрированных на этом устройстве.
    """
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    salt: Mapped[bytes] = mapped_column(LargeBinary)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    user: Mapped["User"] = relationship(back_populates="account")
    chat_keys: Mapped[list["ChatKey"]] = relationship(back_populates="account")


class User(Base):
    """
    Локальный кэш пользователей (и своих, и чужих контактов).
    Собственный аккаунт имеет связанный Account; у контактов account = None.
    """
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    # Исправлено: было last_onlice (опечатка)
    last_online: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=True
    )

    account: Mapped["Account | None"] = relationship(back_populates="user", uselist=False)
    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="user")
    messages: Mapped[list["Message"]] = relationship(back_populates="user")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="user")


class ChatKey(Base):
    """
    Расшифрованный (или подготовленный к расшифровке) ключ чата для аккаунта.
    Связывает аккаунт пользователя с конкретным чатом.
    """
    __tablename__ = "chat_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Групповой ключ чата, зашифрованный публичным ключом владельца аккаунта
    encrypted_group_key: Mapped[bytes] = mapped_column(LargeBinary)

    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))

    account: Mapped["Account"] = relationship(back_populates="chat_keys")
    chat: Mapped["Chat"] = relationship(back_populates="chat_keys")


class Chat(Base):
    """Локальный кэш чата с отображаемым именем."""
    __tablename__ = "chats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Добавлено: поля name и display_name, которые сервер возвращает в /api/get_chats
    name: Mapped[str] = mapped_column(String, unique=True)
    display_name: Mapped[str] = mapped_column(String)

    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="chat")
    messages: Mapped[list["Message"]] = relationship(back_populates="chat")
    chat_keys: Mapped[list["ChatKey"]] = relationship(back_populates="chat")


class ChatMembership(Base):
    """Участие конкретного пользователя в чате."""
    __tablename__ = "chat_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    chat: Mapped["Chat"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship(back_populates="memberships")


class Message(Base):
    """
    Локально сохранённое сообщение.
    Хранится в зашифрованном виде; расшифровывается через ChatKey чата.
    """
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    encrypted_content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))

    user: Mapped["User"] = relationship(back_populates="messages")
    chat: Mapped["Chat"] = relationship(back_populates="messages")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="message")


class MessageRead(Base):
    """Отметка о прочтении сообщения конкретным пользователем."""
    __tablename__ = "message_reads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    message: Mapped["Message"] = relationship(back_populates="reads")
    user: Mapped["User"] = relationship(back_populates="reads")
