"""Taint tag enumeration shared across all taint analysis modules."""
from __future__ import annotations

from enum import Enum


class TaintTag(str, Enum):
    INTENT = "INTENT"
    URI = "URI"
    FILE_PATH = "FILE_PATH"
    URL = "URL"
    SQL = "SQL"
    DEX_PATH = "DEX_PATH"
    USER_INPUT = "USER_INPUT"
    OTHER = "OTHER"
