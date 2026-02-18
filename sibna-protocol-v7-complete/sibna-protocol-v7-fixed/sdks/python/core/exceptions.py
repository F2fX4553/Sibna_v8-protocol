"""
Sibna Exception Types
=====================

Custom exceptions for the Sibna Python SDK.
"""

from typing import Optional


class SibnaError(Exception):
    """Base exception for all Sibna errors."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


class NetworkError(SibnaError):
    """Network-related errors (connection, timeout, etc.)."""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message, code="NETWORK_ERROR")
        self.status_code = status_code


class AuthError(SibnaError):
    """Authentication and authorization errors."""

    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, code="AUTH_ERROR")


class CryptoError(SibnaError):
    """Cryptographic operation errors."""

    def __init__(self, message: str):
        super().__init__(message, code="CRYPTO_ERROR")


class SessionError(SibnaError):
    """Session-related errors."""

    def __init__(self, message: str, session_id: Optional[str] = None):
        super().__init__(message, code="SESSION_ERROR")
        self.session_id = session_id


class KeyNotFoundError(SibnaError):
    """Key not found in keystore."""

    def __init__(self, key_id: str):
        super().__init__(f"Key not found: {key_id}", code="KEY_NOT_FOUND")
        self.key_id = key_id


class InvalidSignatureError(SibnaError):
    """Signature verification failed."""

    def __init__(self, message: str = "Invalid signature"):
        super().__init__(message, code="INVALID_SIGNATURE")


class ReplayAttackError(SibnaError):
    """Replay attack detected."""

    def __init__(self, message: str = "Replay attack detected"):
        super().__init__(message, code="REPLAY_ATTACK")


class RateLimitError(NetworkError):
    """Rate limit exceeded."""

    def __init__(self, retry_after: Optional[int] = None):
        super().__init__("Rate limit exceeded", status_code=429)
        self.retry_after = retry_after
