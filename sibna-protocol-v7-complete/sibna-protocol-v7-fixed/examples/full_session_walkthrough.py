#!/usr/bin/env python3
"""
Sibna Protocol - Full Session Walkthrough Example
==================================================

This example demonstrates the complete flow:
1. Identity key generation
2. Prekey bundle creation
3. X3DH handshake
4. Double Ratchet message exchange
"""

import sys
import os

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../sdks/python'))

from sibna import Client


def main():
    print("=" * 60)
    print("Sibna Protocol - Full Session Walkthrough")
    print("=" * 60)

    # Step 1: Create clients
    print("\n[1] Creating clients...")
    alice = Client("alice", "http://localhost:8000")
    bob = Client("bob", "http://localhost:8000")
    print("    Alice and Bob created")

    # Step 2: Register with server
    print("\n[2] Registering with server...")
    print("    (Note: Server must be running)")
    alice.register()
    bob.register()
    print("    Registration complete")

    # Step 3: Alice sends a message to Bob
    print("\n[3] Alice sends message to Bob...")
    alice.send("bob", b"Hello Bob! This is a secret message from Alice.")
    print("    Message queued")

    # Step 4: Start background workers
    print("\n[4] Starting message processing...")

    def on_bob_message(msg):
        print(f"    Bob received: {msg.content.decode()}")

    bob.on_message(on_bob_message)
    bob.start()
    alice.start()

    # Step 5: Wait for message delivery
    print("\n[5] Waiting for message delivery...")
    import time
    time.sleep(3)

    # Step 6: Bob replies
    print("\n[6] Bob replies to Alice...")
    bob.send("alice", b"Hi Alice! I received your message. This is my reply.")

    time.sleep(3)

    # Step 7: Check pending messages
    print("\n[7] Checking pending messages...")
    print(f"    Alice pending: {alice.get_pending_count()}")
    print(f"    Bob pending: {bob.get_pending_count()}")

    # Step 8: Cleanup
    print("\n[8] Stopping clients...")
    alice.stop()
    bob.stop()

    print("\n" + "=" * 60)
    print("Walkthrough complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
