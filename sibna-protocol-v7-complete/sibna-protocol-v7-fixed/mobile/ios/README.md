# iOS SDK

Swift SDK for Sibna secure messaging on iOS.

## Installation

### Swift Package Manager

```swift
dependencies: [
    .package(url: "https://github.com/sibna/protocol.git", from: "7.0.0")
]
```

### CocoaPods

```ruby
pod 'Sibna', '~> 7.0.0'
```

## Usage

```swift
import Sibna

// Initialize
let config = SibnaConfig()
let sibna = Sibna(config: config)

// Generate identity
let identity = try sibna.generateIdentity()
print("X25519 Public Key: \(identity.x25519PublicKeyHex)")

// Create session
let session = try sibna.createSession(peerId: "peer_id".data(using: .utf8)!)

// Encrypt
let encrypted = try sibna.encrypt(
    peerId: "peer_id".data(using: .utf8)!,
    plaintext: "Hello!".data(using: .utf8)!
)

// Decrypt
let decrypted = try sibna.decrypt(
    peerId: "peer_id".data(using: .utf8)!,
    ciphertext: encrypted
)
```

## Features

- X3DH Key Agreement
- Double Ratchet
- Group Messaging
- Forward Secrecy
- Post-Compromise Security

## Requirements

- iOS 14.0+
- Swift 5.7+
- Xcode 14+

## License

Apache-2.0 OR MIT
