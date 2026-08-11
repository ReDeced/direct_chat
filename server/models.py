from datetime import datetime, timezone
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import DateTime, ForeignKey, Integer, String, LargeBinary, UniqueConstraint


def utcnow() -> datetime:
    """Текущее время UTC (aware). datetime.utcnow() устарел в Python 3.12."""
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    ...


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)
    password_hash: Mapped[str] = mapped_column(String)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    last_online: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="user")
    pending_messages: Mapped[list["Message"]] = relationship(back_populates="user")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="user")
    sessions: Mapped[list["SessionModel"]] = relationship(back_populates="user")
    created_chats: Mapped[list["Chat"]] = relationship(back_populates="creator")


class SessionModel(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(primary_key=True)
    hashed_token: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    user: Mapped["User"] = relationship(back_populates="sessions")


class ChatMembership(Base):
    __tablename__ = "chat_memberships"

    __table_args__ = (
        UniqueConstraint("user_id", "chat_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    encrypted_group_key: Mapped[bytes] = mapped_column(LargeBinary)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id", ondelete="CASCADE"))

    user: Mapped["User"] = relationship(back_populates="memberships")
    chat: Mapped["Chat"] = relationship(back_populates="members")


class Chat(Base):
    __tablename__ = "chats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String, unique=True)
    display_name: Mapped[str] = mapped_column(String)
    creator_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    creator: Mapped["User"] = relationship(back_populates="created_chats")
    members: Mapped[list["ChatMembership"]] = relationship(back_populates="chat")
    pending_messages: Mapped[list["Message"]] = relationship(back_populates="chat")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id", ondelete="CASCADE"))
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    user: Mapped["User"] = relationship(back_populates="pending_messages")
    chat: Mapped["Chat"] = relationship(back_populates="pending_messages")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="message")


class MessageRead(Base):
    __tablename__ = "message_reads"

    __table_args__ = (
        UniqueConstraint("message_id", "user_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    message: Mapped["Message"] = relationship(back_populates="reads")
    user: Mapped["User"] = relationship(back_populates="reads")
