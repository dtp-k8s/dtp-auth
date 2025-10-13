"""Database management for the authentication service."""

import logging

from argon2 import PasswordHasher
from sortedcontainers import SortedSet
from sqlmodel import Session, SQLModel, create_engine, select

from dtp.auth.models import User, settings

engine = create_engine(str(settings.pg_dsn))
hasher = PasswordHasher()
logger = logging.getLogger("dtp.auth")


def init_db():
    """Initialize the database.

    This is idempotent and will only create the tables and default admin user if they do not exist.
    In a production environment, use a proper migration tool like Alembic instead.
    """
    SQLModel.metadata.create_all(engine, checkfirst=True)

    with Session(engine) as session:
        # Create a default admin user if it doesn't exist
        query = select(User).where(User.username == "admin")
        user = session.exec(query).one_or_none()
        if user is None:
            admin_user = User(
                username="admin",
                password_hash=hasher.hash(settings.admin_password),
                scopes="admin",
            )
            session.add(admin_user)
            session.commit()
            logger.info("Created new 'admin' user.")
        else:
            logger.info("User 'admin' already exists; skipping creation.")


def validate_user(username: str, password: str) -> User | None:
    """Validate user credentials.

    Returns the user object if the credentials are valid, otherwise None.  For security reasons,
    we do not differentiate between "user does not exist" and "invalid password".

    Args:
        username: The username to validate.
        password: The password to validate.

    Returns:
        The User object if the credentials are valid, otherwise None.
    """
    with Session(engine) as session:
        query = select(User).where(User.username == username)
        user = session.exec(query).one_or_none()
        if user is None:
            return None
        try:
            hasher.verify(user.password_hash, password)
            return user
        except Exception:
            return None


def create_user(username: str, password: str, scopes: list[str]) -> User:
    """Create a new user.

    Args:
        username: The username for the new user.
        password: The password for the new user.
        scopes: The scopes/permissions for the new user.

    Returns:
        The created User object.

    Raises:
        ValueError: If the username already exists.
    """
    scopes_str = ";".join(SortedSet(scopes))
    with Session(engine) as session:
        # Check if the username already exists
        user = session.exec(select(User).where(User.username == username)).one_or_none()
        if user is not None:
            raise ValueError(f"User '{username}' already exists.")

        # Create the new user
        new_user = User(
            username=username,
            password_hash=hasher.hash(password),
            scopes=scopes_str,
        )
        session.add(new_user)

        # Commit the transaction and refresh the instance to get the generated ID
        session.commit()
        session.refresh(new_user)

        return new_user


def update_user(
    username: str,
    password: str,
    new_username: str | None = None,
    new_password: str | None = None,
    new_scopes: list[str] | None = None,
):
    """Update an existing user's information.

    Args:
        username: The current username of the user to update.
        password: The current password of the user to update.
        new_username: The new username for the user (optional).
        new_password: The new password for the user (optional).
        new_scopes: The new scopes/permissions for the user (optional).

    Returns:
        The updated User object.
    """
    user = validate_user(username, password)
    if user is None:
        raise ValueError("Invalid username or password.")

    with Session(engine) as session:
        if new_username is not None:
            if username == "admin":
                raise ValueError(
                    "Cannot change the username of the 'admin' user. "
                    "Create a new user with admin rights instead."
                )
            # Check for username collision
            collision_user = session.exec(
                select(User).where(User.username == new_username)
            ).one_or_none()
            if collision_user is not None and collision_user.id != user.id:
                raise ValueError(f"Username '{new_username}' is already taken.")
            # If no collision, update the username
            user.username = new_username
        if new_password is not None:
            user.password_hash = hasher.hash(new_password)
        if new_scopes is not None:
            user.scopes = ";".join(SortedSet(new_scopes))

        # Update the user in the database, commit the transaction, and refresh the instance
        session.add(user)
        session.commit()
        session.refresh(user)

        return user


def delete_user(username: str, password: str):
    """Delete a user.

    Args:
        username: The username of the user to delete.
        password: The password of the user to delete.

    Raises:
        ValueError: If the user does not exist or if the credentials are invalid.
    """
    user = validate_user(username, password)
    if user is None:
        raise ValueError("Invalid username or password.")
    if username == "admin":
        raise ValueError("Cannot delete the 'admin' user.")

    with Session(engine) as session:
        session.delete(user)
        session.commit()

    return user  # Return the deleted user


def delete_user_as_admin(admin_username: str, admin_password: str, target_username: str):
    """Delete a user as an admin.

    Args:
        admin_username: The username of the admin user.
        admin_password: The password of the admin user.
        target_username: The username of the user to delete.
    """
    admin_user = validate_user(admin_username, admin_password)
    if admin_user is None or (
        "admin" not in admin_user.scopes and "users:admin" not in admin_user.scopes
    ):
        raise ValueError("Invalid admin credentials.")

    with Session(engine) as session:
        target_user = session.exec(
            select(User).where(User.username == target_username)
        ).one_or_none()
        if target_user is None:
            raise ValueError(f"User '{target_username}' does not exist.")

        session.delete(target_user)
        session.commit()

    return target_user  # Return the deleted user
