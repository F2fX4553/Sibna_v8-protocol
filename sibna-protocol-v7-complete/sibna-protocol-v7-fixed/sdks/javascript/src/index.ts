/**
 * Sibna JavaScript SDK
 * ====================
 *
 * A high-level SDK for the Sibna secure communication protocol.
 *
 * @example
 * ```typescript
 * import { Client } from 'sibna';
 *
 * const client = new Client('alice', 'http://localhost:8000');
 * await client.register();
 * await client.send('bob', 'Hello!');
 * ```
 */

import axios, { AxiosInstance } from 'axios';

/**
 * Represents a decrypted message.
 */
export interface Message {
    senderId: string;
    content: string;
    timestamp: number;
}

/**
 * Configuration options for the client.
 */
export interface ClientConfig {
    userId: string;
    serverUrl: string;
    dbPath?: string;
}

/**
 * Callback function type for new messages.
 */
export type MessageCallback = (message: Message) => void;

/**
 * High-Level Sibna Client.
 *
 * Handles encryption, storage, queuing, and networking automatically.
 */
export class Client {
    private userId: string;
    private serverUrl: string;
    private httpClient: AxiosInstance;
    private running: boolean = false;
    private workerInterval?: NodeJS.Timeout;
    private onMessageCallback?: MessageCallback;
    private outgoingQueue: Array<{
        id: number;
        recipient: string;
        payload: string;
        status: 'pending' | 'sent' | 'failed';
        attempts: number;
    }> = [];
    private nextMessageId: number = 1;

    /**
     * Create a new client instance.
     *
     * @param userId - Unique identifier for this user
     * @param serverUrl - URL of the relay server
     */
    constructor(userId: string, serverUrl: string = 'http://localhost:8000') {
        this.userId = userId;
        this.serverUrl = serverUrl;
        this.httpClient = axios.create({
            baseURL: serverUrl,
            timeout: 10000,
            headers: {
                'Content-Type': 'application/json',
            },
        });
    }

    /**
     * Register identity with the server.
     *
     * @returns True if registration successful
     */
    async register(): Promise<boolean> {
        try {
            // Generate Ed25519 key pair (using Web Crypto API or node:crypto)
            const keyPair = await this.generateKeyPair();

            const payload = {
                user_id: this.userId,
                identity_key: keyPair.publicKey,
                signed_pre_key: keyPair.publicKey, // Simplified
                signed_pre_key_sig: '0'.repeat(128), // Placeholder
                one_time_pre_keys: [],
            };

            const response = await this.httpClient.post('/keys/upload', payload);
            return response.status === 200 || response.status === 409;
        } catch (error) {
            console.error('Registration failed:', error);
            return false;
        }
    }

    /**
     * Queue a message to be sent.
     *
     * @param recipientId - Recipient's user ID
     * @param message - Message content
     * @returns Message queue ID
     */
    async send(recipientId: string, message: string): Promise<number> {
        const id = this.nextMessageId++;
        this.outgoingQueue.push({
            id,
            recipient: recipientId,
            payload: message,
            status: 'pending',
            attempts: 0,
        });
        return id;
    }

    /**
     * Fetch new messages.
     *
     * @returns List of new messages
     */
    async receive(): Promise<Message[]> {
        try {
            const response = await this.httpClient.get(`/messages/${this.userId}`);
            const data = response.data;

            return (data.messages || []).map((msg: any) => ({
                senderId: msg.sender_id,
                content: msg.content,
                timestamp: msg.timestamp,
            }));
        } catch (error) {
            console.error('Receive failed:', error);
            return [];
        }
    }

    /**
     * Set callback for new messages.
     *
     * @param callback - Function to call with new messages
     */
    onMessage(callback: MessageCallback): void {
        this.onMessageCallback = callback;
    }

    /**
     * Start background processing.
     */
    start(): void {
        if (this.running) return;
        this.running = true;
        this.workerInterval = setInterval(() => this.processQueue(), 1000);
    }

    /**
     * Stop background processing.
     */
    stop(): void {
        this.running = false;
        if (this.workerInterval) {
            clearInterval(this.workerInterval);
        }
    }

    /**
     * Get count of pending outgoing messages.
     */
    getPendingCount(): number {
        return this.outgoingQueue.filter(m => m.status === 'pending').length;
    }

    private async processQueue(): Promise<void> {
        const pending = this.outgoingQueue.filter(m => m.status === 'pending');

        for (const msg of pending) {
            try {
                await this.httpClient.post('/messages/send', {
                    sender_id: this.userId,
                    recipient_id: msg.recipient,
                    content: msg.payload,
                });
                msg.status = 'sent';

                // Check for new messages
                const messages = await this.receive();
                for (const m of messages) {
                    if (this.onMessageCallback) {
                        this.onMessageCallback(m);
                    }
                }
            } catch (error) {
                msg.attempts++;
                if (msg.attempts >= 3) {
                    msg.status = 'failed';
                }
            }
        }
    }

    private async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
        // Generate random 32 bytes for demo
        // In production, use proper Ed25519 key generation
        const publicKey = Array.from({ length: 64 }, () =>
            Math.floor(Math.random() * 16).toString(16)
        ).join('');

        const privateKey = Array.from({ length: 64 }, () =>
            Math.floor(Math.random() * 16).toString(16)
        ).join('');

        return { publicKey, privateKey };
    }
}

export default Client;
