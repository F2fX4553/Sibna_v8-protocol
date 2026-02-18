# Sibna JavaScript SDK

A high-level JavaScript/TypeScript SDK for the Sibna secure communication protocol.

## Installation

```bash
npm install sibna
# or
yarn add sibna
```

## Usage

```javascript
const { Client } = require('sibna');

// Create a client
const alice = new Client('alice', 'http://localhost:8000');

// Register with server
await alice.register();

// Send a message
await alice.send('bob', 'Hello Bob!');

// Receive messages
const messages = await alice.receive();
console.log(messages);

// Set up message callback
alice.onMessage((msg) => {
    console.log(`New message from ${msg.senderId}: ${msg.content}`);
});

// Start background processing
alice.start();
```

## API Reference

### Client

#### `new Client(userId, serverUrl)`

Create a new client instance.

- `userId` - Unique identifier for this user
- `serverUrl` - URL of the relay server

#### `register(): Promise<boolean>`

Register identity with the server.

#### `send(recipientId, message): Promise<number>`

Queue a message to be sent.

#### `receive(): Promise<Message[]>`

Fetch new messages.

#### `onMessage(callback): void`

Set callback for new messages.

#### `start(): void`

Start background processing.

#### `stop(): void`

Stop background processing.

## License

Apache-2.0 or MIT
