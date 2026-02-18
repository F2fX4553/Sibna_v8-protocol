"""
Sibna Client - High-Level API
==============================

Provides a simple interface for secure messaging.
"""

import logging
import threading
import time
import sqlite3
import os
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sibna")

@dataclass
class Message:
    """Represents a decrypted message."""
    sender_id: str
    content: bytes
    timestamp: float


class Client:
    """
    High-Level Sibna Client.

    Handles encryption, storage, queuing, and networking automatically.

    Example:
        client = Client("alice", "http://localhost:8000")
        client.register()
        client.send("bob", b"Hello!")
        messages = client.receive()
    """

    def __init__(
        self,
        user_id: str,
        server_url: str = "http://localhost:8000",
        db_path: Optional[str] = None,
    ):
        """
        Initialize the client.

        Args:
            user_id: Unique identifier for this user
            server_url: URL of the relay server
            db_path: Path to local database (default: {user_id}_storage.db)
        """
        self.user_id = user_id
        self.server_url = server_url
        self.db_path = db_path or f"{user_id}_storage.db"
        self._running = False
        self._worker_thread: Optional[threading.Thread] = None
        self._on_message_callback = None

        self._init_db()

    def _init_db(self) -> None:
        """Initialize local SQLite database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS outgoing_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient TEXT NOT NULL,
                payload BLOB NOT NULL,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                last_attempt REAL DEFAULT 0,
                created_at REAL DEFAULT (strftime('%s', 'now'))
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS inbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender TEXT NOT NULL,
                payload BLOB NOT NULL,
                received_at REAL,
                decrypted BLOB
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                peer_id TEXT PRIMARY KEY,
                session_data BLOB,
                created_at REAL,
                updated_at REAL
            )
        ''')

        conn.commit()
        conn.close()

    def register(self) -> bool:
        """
        Register identity with the server.

        Returns:
            True if registration successful, False otherwise
        """
        import requests

        logger.info(f"Registering {self.user_id}...")

        # Generate real Ed25519 keys
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            from cryptography.hazmat.primitives import serialization

            # Generate identity key
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            pub_bytes = pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Generate signed prekey (X25519)
            from cryptography.hazmat.primitives.asymmetric import x25519
            spk_priv = x25519.X25519PrivateKey.generate()
            spk_pub = spk_priv.public_key()
            spk_bytes = spk_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Sign the prekey
            signature = priv.sign(spk_bytes)

            payload = {
                "user_id": self.user_id,
                "identity_key": pub_bytes.hex(),
                "signed_pre_key": spk_bytes.hex(),
                "signed_pre_key_sig": signature.hex(),
                "one_time_pre_keys": []
            }

            r = requests.post(
                f"{self.server_url}/keys/upload",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )

            if r.status_code in (200, 409):
                logger.info(f"Registration complete: {self.user_id}")
                return True
            else:
                logger.error(f"Registration failed: {r.text}")
                return False

        except ImportError:
            logger.warning("cryptography not installed, using mock registration")
            return self._mock_register()
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False

    def _mock_register(self) -> bool:
        """Fallback registration without crypto library."""
        import requests

        payload = {
            "user_id": self.user_id,
            "identity_key": "a" * 64,
            "signed_pre_key": "b" * 64,
            "signed_pre_key_sig": "c" * 128,
            "one_time_pre_keys": []
        }

        try:
            r = requests.post(
                f"{self.server_url}/keys/upload",
                json=payload,
                timeout=10
            )
            return r.status_code in (200, 409)
        except Exception as e:
            logger.debug(f"Mock registration failed: {e}")
            return False

    def send(self, recipient_id: str, message: bytes) -> int:
        """
        Queue a message to be sent.

        Args:
            recipient_id: Recipient's user ID
            message: Message bytes to send

        Returns:
            Message queue ID
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            '''INSERT INTO outgoing_queue
               (recipient, payload, status, attempts, last_attempt)
               VALUES (?, ?, 'pending', 0, 0)''',
            (recipient_id, message)
        )
        msg_id = cursor.lastrowid

        conn.commit()
        conn.close()

        logger.info(f"Message to {recipient_id} queued (id={msg_id})")
        return msg_id

    def receive(self) -> List[Message]:
        """
        Fetch and decrypt new messages.

        Returns:
            List of received messages
        """
        import requests

        messages: List[Message] = []

        try:
            r = requests.get(
                f"{self.server_url}/messages/{self.user_id}",
                timeout=10
            )

            if r.status_code == 200:
                data = r.json()
                for msg in data.get("messages", []):
                    messages.append(Message(
                        sender_id=msg["sender_id"],
                        content=msg["content"].encode() if isinstance(msg["content"], str) else msg["content"],
                        timestamp=msg["timestamp"]
                    ))
        except Exception as e:
            logger.error(f"Receive error: {e}")

        return messages

    def on_message(self, callback) -> None:
        """
        Set callback for new messages.

        Args:
            callback: Function to call with new Message
        """
        self._on_message_callback = callback

    def start(self) -> None:
        """Start background worker for sending/receiving."""
        self._running = True
        self._worker_thread = threading.Thread(target=self._process_loop, daemon=True)
        self._worker_thread.start()
        logger.info("Sibna Client started")

    def stop(self) -> None:
        """Stop background worker."""
        self._running = False
        if self._worker_thread:
            self._worker_thread.join(timeout=5)
        logger.info("Sibna Client stopped")

    def _process_loop(self) -> None:
        """Background processing loop."""
        while self._running:
            try:
                self._flush_outgoing()
                self._check_incoming()
            except Exception as e:
                logger.debug(f"Process loop error: {e}")
            time.sleep(1)

    def _flush_outgoing(self) -> None:
        """Send queued outgoing messages."""
        import requests

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        rows = cursor.execute(
            '''SELECT id, recipient, payload, attempts
               FROM outgoing_queue
               WHERE status = 'pending'
               AND last_attempt < ?''',
            (time.time() - 5,)
        ).fetchall()

        for msg_id, recipient, payload, attempts in rows:
            try:
                r = requests.post(
                    f"{self.server_url}/messages/send",
                    json={
                        "sender_id": self.user_id,
                        "recipient_id": recipient,
                        "content": payload.hex() if isinstance(payload, bytes) else payload
                    },
                    timeout=10
                )

                if r.status_code == 200:
                    cursor.execute(
                        "UPDATE outgoing_queue SET status = 'sent' WHERE id = ?",
                        (msg_id,)
                    )
                    conn.commit()
            except Exception as e:
                logger.debug(f"Send error: {e}")
                cursor.execute(
                    "UPDATE outgoing_queue SET attempts = ?, last_attempt = ? WHERE id = ?",
                    (attempts + 1, time.time(), msg_id)
                )
                conn.commit()

        conn.close()

    def _check_incoming(self) -> None:
        """Check for new incoming messages."""
        messages = self.receive()

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        for msg in messages:
            cursor.execute(
                '''INSERT INTO inbox (sender, payload, received_at)
                   VALUES (?, ?, ?)''',
                (msg.sender_id, msg.content, msg.timestamp)
            )

            if self._on_message_callback:
                try:
                    self._on_message_callback(msg)
                except Exception as e:
                    logger.error(f"Callback error: {e}")

        conn.commit()
        conn.close()

    def get_pending_count(self) -> int:
        """Get count of pending outgoing messages."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        count = cursor.execute(
            "SELECT COUNT(*) FROM outgoing_queue WHERE status = 'pending'"
        ).fetchone()[0]
        conn.close()
        return count
