from datetime import UTC, datetime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import DateTime, ForeignKey, Integer, String, LargeBinary

class Base(DeclarativeBase):
    ...

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String, unique=True)

    password_hash: Mapped[bytes] = mapped_column(LargeBinary)
    
    public_key: Mapped[bytes] = mapped_column(LargeBinary)

    last_online: Mapped[bytes] = mapped_column(DateTime)
    
    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="user")
    pending_messages: Mapped[list["Message"]] = relationship(back_populates="user")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="user")


class ChatMembership(Base):
    __tablename__ = "chat_memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id", ondelete="CASCADE"))

    user: Mapped["User"] = relationship(back_populates="memberships")
    chat: Mapped["Chat"] = relationship(back_populates="members")


class Chat(Base):
    __tablename__ = "chats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    members: Mapped[list["ChatMembership"]] = relationship(back_populates="chat")
    pending_messages: Mapped[list["Message"]] = relationship(back_populates="chat")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id", ondelete="CASCADE"))
    
    content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(UTC))

    user: Mapped["User"] = relationship(back_populates="pending_messages")
    chat: Mapped["Chat"] = relationship(back_populates="pending_messages")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="message")


class MessageRead(Base):
    __tablename__ = "messages_read"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    message: Mapped["Message"] = relationship(back_populates="reads")
    user: Mapped["User"] = relationship(back_populates="reads")
