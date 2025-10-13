"""Tests for the dtp.auth.db module.

To run these tests with output, use:
    uv run pytest -s pytests/test_db.py

To run all tests (summary output only), use:
    uv run pytest pytests/
"""

from uuid import uuid4

import pytest

from dtp.auth import db


@pytest.fixture(scope="session", autouse=True)
def init_db():
    """Initialize the database for testing.

    This is idempotent and will only create the tables and default admin user if they do not exist.
    """
    db.init_db()


def test_db_operations():
    """Test database operations: create, validate, update, and delete user."""
    print("\n")  # New line before test output

    tag = str(uuid4())[:8]
    username = f"testuser_{tag}"

    # Test user creation
    user = db.create_user(username, "password", scopes=["basic"])
    assert user.username == username
    assert db.validate_user(username, "password") is not None  # Simulate login attempt
    print(f"Created test user: {username}")

    # Test user update
    db.update_user(username, "password", new_password="new_password")
    assert db.validate_user(username, "password") is None  # Old password should fail
    assert db.validate_user(username, "new_password") is not None  # New password should work
    print(f"Updated password for user: {username}")

    # Test user deletion by self
    deleted_user = db.delete_user(username, "new_password")
    assert deleted_user.username == username
    assert db.validate_user(username, "new_password") is None  # User should no longer exist
    print(f"Deleted test user: {username}")

    # Test user deletion by admin
    db.create_user(username, "new_password", scopes=["basic"])
    print(f"Re-created test user: {username}")
    deleted_user2 = db.delete_user_as_admin("admin", db.settings.admin_password, username)
    assert deleted_user2.username == username
    assert deleted_user2.id != deleted_user.id  # Different users since we deleted and recreated
    print(f"Deleted test user as admin: {username}")
