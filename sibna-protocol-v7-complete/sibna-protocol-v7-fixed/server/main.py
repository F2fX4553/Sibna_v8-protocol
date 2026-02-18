"""
Sibna Relay Server - Secure Implementation
===========================================

A production-ready relay server for the Sibna protocol.
Implements secure key distribution and message relay.

Security Features:
- Rate limiting (DoS protection)
- Input validation
- SQL injection prevention
- Secure headers
- Signature verification
- Message TTL
"""

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import uvicorn
import sqlite3
import time
import re
import os
import secrets
from collections import defaultdict
import threading
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sibna-relay")

app = FastAPI(
    title="Sibna Relay Server",
    description="Secure message relay for end-to-end encrypted communication",
    version="7.0.0",
    docs_url=None,
    redoc_url=None
)

# --- Security Configuration ---
MAX_REQUESTS_PER_MINUTE = 60
MESSAGE_TTL = 86400  # 24 hours
MAX_MESSAGES_PER_USER = 100
MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB
DB_PATH = os.environ.get("SIBNA_DB_PATH", "sibna_relay.db")

# --- Database Setup ---
def init_db():
    """Initialize database with secure schema."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            identity_key TEXT NOT NULL,
            signed_pre_key TEXT NOT NULL,
            signed_pre_key_sig TEXT NOT NULL,
            created_at REAL NOT NULL,
            last_seen REAL
        )
    ''')

    # One-Time Keys Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS one_time_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT NOT NULL,
            key_data TEXT NOT NULL,
            created_at REAL NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_otk_user ON one_time_keys(user_id)')

    # Messages Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp REAL NOT NULL,
            FOREIGN KEY(recipient_id) REFERENCES users(user_id) ON DELETE CASCADE
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_recipient ON messages(recipient_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_msg_timestamp ON messages(timestamp)')

    conn.commit()
    conn.close()

init_db()

# --- Background Cleanup ---
def purge_expired_messages():
    """Periodically remove expired messages."""
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            cutoff = time.time() - MESSAGE_TTL
            cursor.execute('DELETE FROM messages WHERE timestamp < ?', (cutoff,))
            count = cursor.rowcount
            conn.commit()
            conn.close()
            if count > 0:
                logger.info(f"Purged {count} expired messages")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
        time.sleep(3600)

cleanup_thread = threading.Thread(target=purge_expired_messages, daemon=True)
cleanup_thread.start()

# --- Rate Limiting ---
request_counts = defaultdict(list)

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    """Prevent DoS attacks with rate limiting."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    # Clean old requests
    request_counts[client_ip] = [t for t in request_counts[client_ip] if t > now - 60]

    if len(request_counts[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content={"detail": "Rate limit exceeded"}
        )

    request_counts[client_ip].append(now)
    return await call_next(request)

# --- Security Headers ---
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Content-Security-Policy"] = "default-src 'none'"
    return response

# --- Payload Size Limit ---
@app.middleware("http")
async def limit_payload_size(request: Request, call_next):
    """Prevent memory exhaustion attacks."""
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > MAX_PAYLOAD_SIZE:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={"detail": "Payload too large"}
        )
    return await call_next(request)

# --- Content-Type Validation ---
@app.middleware("http")
async def strict_content_type(request: Request, call_next):
    """Prevent MIME sniffing attacks."""
    if request.method in ["POST", "PUT", "PATCH"]:
        ct = request.headers.get("content-type", "")
        if "application/json" not in ct:
            return JSONResponse(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                content={"detail": "Content-Type must be application/json"}
            )
    return await call_next(request)

# --- Models ---
class PreKeyBundle(BaseModel):
    """Prekey bundle for registration."""
    user_id: str = Field(..., min_length=3, max_length=32)
    identity_key: str = Field(..., min_length=64, max_length=64)
    signed_pre_key: str = Field(..., min_length=64, max_length=64)
    signed_pre_key_sig: str = Field(..., min_length=128, max_length=128)
    one_time_pre_keys: List[str] = Field(default_factory=list)

    @field_validator('user_id')
    @classmethod
    def validate_user_id(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('user_id must be alphanumeric with _ or -')
        return v

    @field_validator('identity_key', 'signed_pre_key')
    @classmethod
    def validate_hex_key(cls, v):
        if not re.match(r'^[0-9a-fA-F]+$', v):
            raise ValueError('Key must be valid hex')
        return v.lower()

class PreKeyResponse(BaseModel):
    """Response for key fetch."""
    identity_key: str
    signed_pre_key: str
    signed_pre_key_sig: str
    one_time_pre_key: Optional[str] = None

class MessageSend(BaseModel):
    """Message send request."""
    sender_id: str = Field(..., min_length=3, max_length=32)
    recipient_id: str = Field(..., min_length=3, max_length=32)
    content: str = Field(..., max_length=65536)

    @field_validator('sender_id', 'recipient_id')
    @classmethod
    def validate_ids(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Invalid ID format')
        return v

# --- Crypto Helpers ---
def verify_signature(identity_key_hex: str, data_hex: str, signature_hex: str) -> bool:
    """Verify Ed25519 signature."""
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519

        id_key_bytes = bytes.fromhex(identity_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        data_bytes = bytes.fromhex(data_hex)

        public_key = ed25519.Ed25519PublicKey.from_public_bytes(id_key_bytes)
        public_key.verify(sig_bytes, data_bytes)
        return True
    except Exception as e:
        logger.debug(f"Signature verification failed: {e}")
        return False

# --- Routes ---
@app.get("/server/info")
def get_server_info():
    """Get server information."""
    return {
        "version": "7.0.0",
        "supported_algorithms": ["X3DH", "DoubleRatchet", "Ed25519", "X25519"],
        "message_ttl": MESSAGE_TTL,
        "max_message_size": 65536
    }

@app.post("/keys/upload")
def upload_keys(bundle: PreKeyBundle):
    """Upload user keys."""
    # Verify signature
    if not verify_signature(bundle.identity_key, bundle.signed_pre_key, bundle.signed_pre_key_sig):
        raise HTTPException(status_code=400, detail="Invalid signature")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check for existing identity (TOFU)
        cursor.execute("SELECT identity_key FROM users WHERE user_id = ?", (bundle.user_id,))
        existing = cursor.fetchone()

        if existing and existing[0] != bundle.identity_key:
            raise HTTPException(status_code=409, detail="Identity key mismatch")

        # Upsert user
        cursor.execute('''
            INSERT INTO users (user_id, identity_key, signed_pre_key, signed_pre_key_sig, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                signed_pre_key = excluded.signed_pre_key,
                signed_pre_key_sig = excluded.signed_pre_key_sig,
                last_seen = excluded.last_seen
        ''', (bundle.user_id, bundle.identity_key, bundle.signed_pre_key,
              bundle.signed_pre_key_sig, time.time(), time.time()))

        # Insert one-time keys
        for key in bundle.one_time_pre_keys:
            if len(key) == 64 and re.match(r'^[0-9a-fA-F]+$', key):
                cursor.execute(
                    'INSERT INTO one_time_keys (user_id, key_data, created_at) VALUES (?, ?, ?)',
                    (bundle.user_id, key.lower(), time.time())
                )

        conn.commit()
        logger.info(f"Keys uploaded for {bundle.user_id}")
        return {"status": "ok"}

    except HTTPException:
        conn.rollback()
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")
    finally:
        conn.close()

@app.get("/keys/{user_id}", response_model=PreKeyResponse)
def get_keys(user_id: str):
    """Fetch user keys."""
    # Validate user_id
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', user_id):
        raise HTTPException(status_code=400, detail="Invalid user ID")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT identity_key, signed_pre_key, signed_pre_key_sig FROM users WHERE user_id = ?',
            (user_id,)
        )
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        identity_key, signed_pre_key, signed_pre_key_sig = user

        # Atomically fetch and delete one one-time key
        otp_key = None
        cursor.execute(
            'SELECT id, key_data FROM one_time_keys WHERE user_id = ? LIMIT 1',
            (user_id,)
        )
        row = cursor.fetchone()
        if row:
            otp_id, otp_key = row
            cursor.execute('DELETE FROM one_time_keys WHERE id = ?', (otp_id,))
            conn.commit()

        return PreKeyResponse(
            identity_key=identity_key,
            signed_pre_key=signed_pre_key,
            signed_pre_key_sig=signed_pre_key_sig,
            one_time_pre_key=otp_key
        )
    finally:
        conn.close()

@app.post("/messages/send")
def send_message(msg: MessageSend):
    """Send a message."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check inbox limit
        cursor.execute("SELECT COUNT(*) FROM messages WHERE recipient_id = ?", (msg.recipient_id,))
        count = cursor.fetchone()[0]
        if count >= MAX_MESSAGES_PER_USER:
            raise HTTPException(status_code=429, detail="Recipient inbox full")

        # Verify sender exists
        cursor.execute("SELECT 1 FROM users WHERE user_id = ?", (msg.sender_id,))
        if not cursor.fetchone():
            raise HTTPException(status_code=404, detail="Sender not found")

        # Insert message
        cursor.execute(
            'INSERT INTO messages (recipient_id, sender_id, content, timestamp) VALUES (?, ?, ?, ?)',
            (msg.recipient_id, msg.sender_id, msg.content, time.time())
        )
        conn.commit()

        return {"status": "sent"}
    finally:
        conn.close()

@app.get("/messages/{user_id}")
def get_messages(user_id: str):
    """Fetch and delete messages."""
    if not re.match(r'^[a-zA-Z0-9_-]{3,32}$', user_id):
        raise HTTPException(status_code=400, detail="Invalid user ID")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        cursor.execute(
            'SELECT sender_id, content, timestamp FROM messages WHERE recipient_id = ? ORDER BY timestamp ASC',
            (user_id,)
        )
        rows = cursor.fetchall()

        messages = [
            {"sender_id": r[0], "content": r[1], "timestamp": r[2]}
            for r in rows
        ]

        # Delete after delivery (forward secrecy)
        cursor.execute('DELETE FROM messages WHERE recipient_id = ?', (user_id,))
        conn.commit()

        return {"messages": messages}
    finally:
        conn.close()

@app.get("/health")
def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "timestamp": time.time()}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
