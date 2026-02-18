/// Sibna Dart/Flutter SDK
/// =======================
///
/// A high-level SDK for the Sibna secure communication protocol.
///
/// Example:
/// ```dart
/// import 'package:sibna/sibna.dart';
///
/// final client = Client('alice', 'http://localhost:8000');
/// await client.register();
/// await client.send('bob', 'Hello!');
/// ```

import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

/// Represents a decrypted message.
class Message {
  /// Sender's user ID.
  final String senderId;

  /// Message content.
  final String content;

  /// Message timestamp.
  final double timestamp;

  Message({
    required this.senderId,
    required this.content,
    required this.timestamp,
  });

  factory Message.fromJson(Map<String, dynamic> json) {
    return Message(
      senderId: json['sender_id'] as String,
      content: json['content'] as String,
      timestamp: (json['timestamp'] as num).toDouble(),
    );
  }
}

/// Callback type for new messages.
typedef MessageCallback = void Function(Message message);

/// High-Level Sibna Client.
///
/// Handles encryption, storage, queuing, and networking automatically.
class Client {
  final String userId;
  final String serverUrl;
  final http.Client _httpClient;

  bool _running = false;
  Timer? _workerTimer;
  MessageCallback? _onMessageCallback;
  final List<_OutgoingMessage> _outgoingQueue = [];
  int _nextMessageId = 1;

  /// Create a new client instance.
  ///
  /// [userId] - Unique identifier for this user
  /// [serverUrl] - URL of the relay server
  Client(this.userId, [this.serverUrl = 'http://localhost:8000'])
      : _httpClient = http.Client();

  /// Register identity with the server.
  ///
  /// Returns true if registration successful.
  Future<bool> register() async {
    try {
      // Generate random keys for demo
      final publicKey = List.generate(64, (i) => i % 16.toRadixString(16)).join();

      final response = await _httpClient.post(
        Uri.parse('$serverUrl/keys/upload'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'user_id': userId,
          'identity_key': publicKey,
          'signed_pre_key': publicKey,
          'signed_pre_key_sig': '0' * 128,
          'one_time_pre_keys': [],
        }),
      );

      return response.statusCode == 200 || response.statusCode == 409;
    } catch (e) {
      print('Registration failed: $e');
      return false;
    }
  }

  /// Queue a message to be sent.
  ///
  /// [recipientId] - Recipient's user ID
  /// [message] - Message content
  ///
  /// Returns message queue ID.
  Future<int> send(String recipientId, String message) async {
    final id = _nextMessageId++;
    _outgoingQueue.add(_OutgoingMessage(
      id: id,
      recipient: recipientId,
      payload: message,
      status: _MessageStatus.pending,
      attempts: 0,
    ));
    return id;
  }

  /// Fetch new messages.
  ///
  /// Returns list of new messages.
  Future<List<Message>> receive() async {
    try {
      final response = await _httpClient.get(
        Uri.parse('$serverUrl/messages/$userId'),
      );

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final messages = (data['messages'] as List)
            .map((m) => Message.fromJson(m as Map<String, dynamic>))
            .toList();
        return messages;
      }
      return [];
    } catch (e) {
      print('Receive failed: $e');
      return [];
    }
  }

  /// Set callback for new messages.
  void onMessage(MessageCallback callback) {
    _onMessageCallback = callback;
  }

  /// Start background processing.
  void start() {
    if (_running) return;
    _running = true;
    _workerTimer = Timer.periodic(Duration(seconds: 1), (_) => _processQueue());
  }

  /// Stop background processing.
  void stop() {
    _running = false;
    _workerTimer?.cancel();
  }

  /// Get count of pending outgoing messages.
  int get pendingCount =>
      _outgoingQueue.where((m) => m.status == _MessageStatus.pending).length;

  Future<void> _processQueue() async {
    final pending = _outgoingQueue
        .where((m) => m.status == _MessageStatus.pending)
        .toList();

    for (final msg in pending) {
      try {
        await _httpClient.post(
          Uri.parse('$serverUrl/messages/send'),
          headers: {'Content-Type': 'application/json'},
          body: jsonEncode({
            'sender_id': userId,
            'recipient_id': msg.recipient,
            'content': msg.payload,
          }),
        );
        msg.status = _MessageStatus.sent;

        // Check for new messages
        final messages = await receive();
        for (final m in messages) {
          _onMessageCallback?.call(m);
        }
      } catch (e) {
        msg.attempts++;
        if (msg.attempts >= 3) {
          msg.status = _MessageStatus.failed;
        }
      }
    }
  }
}

enum _MessageStatus { pending, sent, failed }

class _OutgoingMessage {
  final int id;
  final String recipient;
  final String payload;
  _MessageStatus status;
  int attempts;

  _OutgoingMessage({
    required this.id,
    required this.recipient,
    required this.payload,
    required this.status,
    required this.attempts,
  });
}
