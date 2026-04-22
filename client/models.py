from datetime import UTC, datetime
from sqlalchemy import DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    ...


class Account(Base):
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    encrypted_private_key: Mapped[bytes] = mapped_column(LargeBinary)
    salt: Mapped[bytes] = mapped_column(LargeBinary)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)

    user: Mapped["User"] = relationship(back_populates="account")
    chat_keys: Mapped[list["ChatKey"]] = relationship(back_populates="account")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    username: Mapped[str] = mapped_column(String)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)

    account: Mapped["Account"] | None = relationship(back_populates="user", uselist=False)
    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="user")
    messages: Mapped[list["Message"]] = relationship(back_populates="user")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="user")


class ChatKey(Base):
    __tablename__ = "chat_keys"

    encrypted_group_key: Mapped[bytes] = mapped_column(LargeBinary)

    account_id: Mapped[int] = mapped_column(ForeignKey("accounts.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))
    
    account: Mapped["Account"] = relationship(back_populates="chat_keys")
    chat: Mapped["Chat"] = relationship(back_populates="chat_keys")


class Chat(Base):
    __tablename__ = "chats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    
    memberships: Mapped[list["ChatMembership"]] = relationship(back_populates="chat")
    messages: Mapped[list["Message"]] = relationship(back_populates="chat")
    chat_keys: Mapped["ChatKey"] = relationship(back_populates="account")


class ChatMembership(Base):
    __tablename__ = "chat_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    chat: Mapped["Chat"] = relationship(back_populates="memberships")
    user: Mapped["User"] = relationship(back_populates="memberships")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    encrypted_content: Mapped[bytes] = mapped_column(LargeBinary)
    created_at: Mapped[datetime] = mapped_column(DateTime)

    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    chat_id: Mapped[int] = mapped_column(ForeignKey("chats.id"))
    
    user: Mapped["User"] = relationship(back_populates="messages")
    chat: Mapped["Chat"] = relationship(back_populates="messages")
    reads: Mapped[list["MessageRead"]] = relationship(back_populates="message")


class MessageRead(Base):
    __tablename__ = "message_reads"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    message_id: Mapped[int] = mapped_column(ForeignKey("messages.id"))
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))

    message: Mapped["Message"] = relationship(back_populates="reads")
    user: Mapped["User"] = relationship(back_populates="reads")

