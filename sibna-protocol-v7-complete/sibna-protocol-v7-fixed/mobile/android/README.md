# Android SDK

Kotlin SDK for Sibna secure messaging on Android.

## Installation

Add to your `build.gradle`:

```gradle
implementation 'io.sibna:sibna-android:7.0.0'
```

## Usage

```kotlin
import io.sibna.sdk.Sibna
import io.sibna.sdk.SibnaConfig

// Initialize
val config = SibnaConfig()
val context = Sibna.initialize(config)

// Generate identity
val identity = context.generateIdentity()
println("X25519 Public Key: ${identity.getX25519PublicKeyHex()}")

// Create session
context.createSession("peer_id")

// Encrypt
val encrypted = context.encrypt("peer_id", "Hello!".toByteArray())

// Decrypt
val decrypted = context.decrypt("peer_id", encrypted)
```

## Features

- X3DH Key Agreement
- Double Ratchet
- Group Messaging
- Forward Secrecy
- Post-Compromise Security

## Requirements

- Android API 24+
- Kotlin 1.8+

## License

Apache-2.0 OR MIT
