"""Utility functions for the authentication service."""

import logging
import sys
from http import HTTPStatus

from pydantic import BaseModel


def json_example(status: int, example: BaseModel):
    """Generate a JSON response example for FastAPI documentation."""
    return {
        "description": HTTPStatus(status).phrase,
        "content": {"application/json": {"example": example.model_dump(mode="json")}},
    }


def text_example(status: int, example: str):
    """Generate a plain text response example for FastAPI documentation."""
    return {
        "description": HTTPStatus(status).phrase,
        "content": {"text/plain": {"example": example}},
    }


def new_logger(name: str):
    """Initialize a logger with the specified name.

    The logger is configured to output to stdout with a format similar to that used by the FastAPI
    logger.
    """
    logger = logging.getLogger(name)
    logger.handlers = [
        logging.StreamHandler(sys.stdout),
    ]
    logger.handlers[0].setFormatter(
        logging.Formatter(
            "%(levelname)10s   %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    logger.propagate = False
    return logger
