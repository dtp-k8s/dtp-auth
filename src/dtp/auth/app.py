"""FastAPI router for authentication in the DT platform."""

from contextlib import asynccontextmanager
from importlib.metadata import metadata, version
from time import time
from typing import Annotated
from uuid import uuid4

from fastapi import FastAPI, Form, HTTPException, Response, status
from fastapi.responses import PlainTextResponse
from jose.exceptions import ExpiredSignatureError, JOSEError
from pydantic import BaseModel

from dtp.auth.db import init_db, validate_user
from dtp.auth.models import LoginCredentials, LoginResponse, SessionToken, settings
from dtp.auth.util import json_example, new_logger, text_example

logger = new_logger("dtp.auth")
logger.setLevel("DEBUG")


@asynccontextmanager
async def lifespan(_):
    """Lifespan context manager for FastAPI application."""
    # Perform any startup actions here
    meta = metadata("dtp-auth").json
    logger.info("")
    logger.info("---------------------------FASTAPI INIT-------------------------------")
    logger.info("Name: %s", meta["name"])
    logger.info("Version: %s", meta["version"])
    logger.info("Authors: %s", meta["author"])
    logger.info("----------------------------------------------------------------------")
    logger.info("")
    init_db()
    # Yield to the FastAPI main loop
    yield
    # Perform any shutdown actions here


app = FastAPI(
    title="DT Auth API",
    summary="Authentication service for the DT platform",
    description="""\
This API provides authentication and authorization services for the DT platform.
Users log in using the `/login` endpoint to receive a JWT session token, which can then be
validated using the `/validate` endpoint.

**Authors:**
- Yin-Chi Chan <ycc39@cam.ac.uk>
- Anandarup Mukherjee <am2910@cam.ac.uk>
""",
    version=version("dtp-auth"),
    license_info={
        "name": "MIT License",
        "identifier": "MIT",
    },
    lifespan=lifespan,
    # Uncomment the following line to disable public OpenAPI schema exposure;
    # this also disables the Swagger UI and ReDoc endpoints.
    # openapi_url=None,
)


class Message(BaseModel):
    """A simple message model.

    Matches the return type of HTTPException, so that both success and error responses can be
    standardized.
    """

    detail: str


DAY_IN_SECONDS = 24 * 60 * 60


@app.get(
    "/health",
    tags=["health"],
    summary="Health Check",
    response_class=PlainTextResponse,
    responses={
        status.HTTP_200_OK: text_example(status.HTTP_200_OK, "OK"),
    },
)
def health_check() -> str:
    """Perform a health check on the API."""
    return "OK"


@app.post(
    "/login",
    tags=["auth"],
    summary="Login",
    responses={
        status.HTTP_200_OK: json_example(status.HTTP_200_OK, LoginResponse(token="example-token")),
        status.HTTP_401_UNAUTHORIZED: json_example(
            status.HTTP_401_UNAUTHORIZED, Message(detail="Unauthorized")
        ),
    },
)
def login(credentials: Annotated[LoginCredentials, Form()]) -> LoginResponse:
    """Log the user in with provided credentials, or return 401 Unauthorized if invalid.

    On success, returns a JWT session token valid for 24 hours.
    """
    if (user := validate_user(credentials.username, credentials.password)) is not None:
        token = SessionToken.new_token(
            claims={
                "iss": "dtp-auth",
                "sub": user.id.hex,
                "exp": int(time()) + DAY_IN_SECONDS,
                "iat": int(time()),
                "jti": uuid4().hex,
            },
            key=settings.jwt_key,
        )
        return LoginResponse(token=token)
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")


@app.post(
    "/validate",
    tags=["auth"],
    summary="Validate Token",
    responses={
        status.HTTP_200_OK: json_example(status.HTTP_200_OK, Message(detail="Token is valid")),
        status.HTTP_401_UNAUTHORIZED: json_example(
            status.HTTP_401_UNAUTHORIZED, Message(detail="Token is invalid or expired")
        ),
    },
)
def validate_token(token: Annotated[str, Form()], response: Response) -> Message:
    """Validate the provided JWT token, or return 401 Unauthorized if invalid or expired.

    If valid, the response will include the 'X-Authorized-User' header with the user ID.  This is
    useful for downstream services to identify the authenticated user, e.g. when using Traefik's
    ForwardAuth middleware.
    """
    try:
        token: SessionToken = SessionToken(token, key=settings.jwt_key)
        response.headers["X-Authorized-User"] = token.sub.hex
        return Message(detail="Token is valid")
    except ExpiredSignatureError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired"
        ) from e
    except JOSEError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is invalid"
        ) from e
