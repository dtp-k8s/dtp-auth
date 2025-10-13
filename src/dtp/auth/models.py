"""Data models for the authentication service."""

from typing import Literal
from uuid import UUID, uuid4

from dotenv import find_dotenv
from jwt_pydantic import JWTPydantic
from pydantic import BaseModel, Field, PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlmodel import Field as SQLField
from sqlmodel import SQLModel


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    pg_dsn: PostgresDsn
    """PostgreSQL Data Source Name (DSN) for database connection."""

    jwt_key: str = Field(min_length=32)
    """Secret key for signing JWT tokens. Must be at least 32 characters long."""

    admin_password: str
    """Initial password for the "admin" user if it does not exist."""

    model_config = SettingsConfigDict(
        env_file=find_dotenv(".env") or None,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()


class LoginCredentials(BaseModel):
    """Model for login credentials."""

    # Use examples to pre-populate Swagger UI form fields
    username: str = Field(examples=["admin"])
    password: str = Field(examples=["secret"])


class SessionToken(JWTPydantic):
    """JWT token model for session management."""

    iss: Literal["dtp-auth"]
    """Issuer.  Always "dtp-auth"."""

    sub: UUID
    """Subject (user identifier)."""

    exp: int
    """Expiration time (as a Unix timestamp)."""

    iat: int
    """Issued at (as a Unix timestamp)."""

    jti: UUID
    """JWT ID (unique identifier for the token)."""


class LoginResponse(BaseModel):
    """Response model for login endpoint."""

    token: str
    """JWT token string."""


class User(SQLModel, table=True):
    """Database model for user authentication records."""

    __tablename__: str = "auth_users"

    id: UUID = SQLField(default_factory=uuid4, primary_key=True)
    """Unique identifier for the user."""

    username: str = SQLField(index=True, unique=True)
    """Username of the user."""

    password_hash: str
    """Password hash of the user."""

    scopes: str
    """Semicolon-separated list of scopes/permissions for the user.

    The "admin" scope grants all permissions.  To grant admin rights for a specific service,
    use "<service>:admin".
    """
