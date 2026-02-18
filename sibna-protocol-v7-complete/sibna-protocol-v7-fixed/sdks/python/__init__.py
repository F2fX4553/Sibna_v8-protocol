"""
Sibna Python SDK
================

A high-level Python client for the Sibna secure communication protocol.

Example:
    from sibna import Client

    client = Client("alice", "http://localhost:8000")
    client.register()

    client.send("bob", "Hello, Bob!")
    messages = client.receive()
"""

__version__ = "7.0.0"
__author__ = "Sibna Team"

# Import main classes
try:
    from .bindings import SecureContext, Config
    _NATIVE_AVAILABLE = True
except ImportError:
    _NATIVE_AVAILABLE = False
    SecureContext = None
    Config = None

from .client import Client

__all__ = ["Client", "SecureContext", "Config", "_NATIVE_AVAILABLE"]
