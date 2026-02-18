/**
 * Sibna Client Wrapper
 * 
 * Provides a high-level JavaScript API for the Sibna WASM module.
 */

import init, { 
  WasmContext, 
  WasmConfig, 
  generate_keypair, 
  random_bytes,
  version 
} from 'sibna-wasm'

let wasmReady = false

export class SibnaClient {
  private context: WasmContext | null = null
  private identity: any = null

  async init(): Promise<void> {
    if (!wasmReady) {
      await init()
      wasmReady = true
    }
    
    const config = new WasmConfig()
    this.context = new WasmContext(config)
  }

  async generateIdentity(): Promise<{
    private_seed: string
    ed25519_public: string
    x25519_public: string
  }> {
    if (!this.context) throw new Error('Context not initialized')
    
    const identity = await this.context.generate_identity()
    this.identity = identity
    return identity
  }

  async createSession(peerId: string): Promise<void> {
    if (!this.context) throw new Error('Context not initialized')
    await this.context.create_session(peerId)
  }

  async performHandshake(
    peerId: string,
    peerIdentityKey: string,
    peerSignedPrekey: string,
    peerOnetimePrekey: string
  ): Promise<string> {
    if (!this.context) throw new Error('Context not initialized')
    
    return await this.context.perform_handshake_initiator(
      peerId,
      peerIdentityKey,
      peerSignedPrekey,
      peerOnetimePrekey
    )
  }

  async encrypt(peerId: string, plaintext: string): Promise<string> {
    if (!this.context) throw new Error('Context not initialized')
    return await this.context.encrypt(peerId, plaintext)
  }

  async decrypt(peerId: string, ciphertext: string): Promise<string> {
    if (!this.context) throw new Error('Context not initialized')
    return await this.context.decrypt(peerId, ciphertext)
  }

  async createGroup(groupId: string): Promise<void> {
    if (!this.context) throw new Error('Context not initialized')
    await this.context.create_group(groupId)
  }

  async encryptGroup(groupId: string, plaintext: string): Promise<string> {
    if (!this.context) throw new Error('Context not initialized')
    return await this.context.encrypt_group(groupId, plaintext)
  }

  async addGroupMember(groupId: string, publicKey: string): Promise<void> {
    if (!this.context) throw new Error('Context not initialized')
    await this.context.add_group_member(groupId, publicKey)
  }

  getDeviceId(): string {
    if (!this.context) throw new Error('Context not initialized')
    return this.context.device_id()
  }

  async listSessions(): Promise<string[]> {
    // In a real implementation, this would query the WASM module
    // For now, return sessions stored in local state
    const stored = localStorage.getItem('sibna_sessions')
    return stored ? JSON.parse(stored) : []
  }

  async listGroups(): Promise<string[]> {
    // In a real implementation, this would query the WASM module
    const stored = localStorage.getItem('sibna_groups')
    return stored ? JSON.parse(stored) : []
  }

  getIdentity() {
    return this.identity
  }

  static getVersion(): string {
    return version()
  }

  static generateRandomBytes(length: number): string {
    return random_bytes(length)
  }

  static async generateKeyPair(): Promise<{
    private_seed: string
    ed25519_public: string
    x25519_public: string
  }> {
    if (!wasmReady) {
      await init()
      wasmReady = true
    }
    return await generate_keypair()
  }
}

// Utility functions
export function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}

export function generateId(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('')
}
