# Sibna Dart/Flutter SDK

A high-level Dart SDK for the Sibna secure communication protocol.

## Installation

Add to your `pubspec.yaml`:

```yaml
dependencies:
  sibna:
    git:
      url: https://github.com/sibna/protocol.git
      path: sdks/dart
```

## Usage

```dart
import 'package:sibna/sibna.dart';

// Create a client
final client = Client('alice', 'http://localhost:8000');

// Register with server
await client.register();

// Send a message
await client.send('bob', 'Hello Bob!');

// Receive messages
final messages = await client.receive();

// Set up message callback
client.onMessage((msg) {
  print('New message from ${msg.senderId}: ${msg.content}');
});

// Start background processing
client.start();
```

## API Reference

### Client

#### `Client(userId, serverUrl)`

Create a new client instance.

#### `register(): Future<bool>`

Register identity with the server.

#### `send(recipientId, message): Future<int>`

Queue a message to be sent.

#### `receive(): Future<List<Message>>`

Fetch new messages.

#### `onMessage(callback): void`

Set callback for new messages.

#### `start(): void`

Start background processing.

#### `stop(): void`

Stop background processing.

## License

Apache-2.0 or MIT
