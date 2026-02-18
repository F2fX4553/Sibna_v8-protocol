import { useState, useEffect } from 'react'

interface ChatWindowProps {
  client: any
  selectedPeer: string | null
  onSelectPeer: (peer: string | null) => void
}

interface Message {
  id: string
  content: string
  sent: boolean
  timestamp: number
}

export function ChatWindow({ client, selectedPeer, onSelectPeer }: ChatWindowProps) {
  const [peerId, setPeerId] = useState('')
  const [message, setMessage] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [peers, setPeers] = useState<string[]>([])
  const [status, setStatus] = useState<string>('')

  useEffect(() => {
    if (client) {
      loadPeers()
    }
  }, [client])

  async function loadPeers() {
    const peerList = await client.listSessions()
    setPeers(peerList)
  }

  async function createSession() {
    if (!peerId.trim()) return
    
    try {
      setStatus('Creating session...')
      await client.createSession(peerId)
      await loadPeers()
      onSelectPeer(peerId)
      setStatus('Session created!')
    } catch (e) {
      setStatus(`Error: ${e}`)
    }
  }

  async function sendMessage() {
    if (!selectedPeer || !message.trim()) return
    
    try {
      const encrypted = await client.encrypt(selectedPeer, message)
      
      // Add to local message list
      const newMessage: Message = {
        id: Date.now().toString(),
        content: message,
        sent: true,
        timestamp: Date.now()
      }
      setMessages(prev => [...prev, newMessage])
      setMessage('')
      
      setStatus('Message encrypted and ready to send')
    } catch (e) {
      setStatus(`Error: ${e}`)
    }
  }

  async function decryptMessage(encryptedHex: string) {
    if (!selectedPeer) return
    
    try {
      const decrypted = await client.decrypt(selectedPeer, encryptedHex)
      
      const newMessage: Message = {
        id: Date.now().toString(),
        content: decrypted,
        sent: false,
        timestamp: Date.now()
      }
      setMessages(prev => [...prev, newMessage])
    } catch (e) {
      setStatus(`Decryption error: ${e}`)
    }
  }

  return (
    <div className="chat-window">
      <div className="chat-sidebar">
        <h3>Sessions</h3>
        
        <div className="new-session">
          <input
            type="text"
            placeholder="Enter peer ID"
            value={peerId}
            onChange={e => setPeerId(e.target.value)}
          />
          <button className="primary" onClick={createSession}>
            Create Session
          </button>
        </div>

        <div className="peer-list">
          {peers.map(peer => (
            <div
              key={peer}
              className={`peer-item ${selectedPeer === peer ? 'active' : ''}`}
              onClick={() => onSelectPeer(peer)}
            >
              <span className="peer-icon">👤</span>
              <span className="peer-name">{peer}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="chat-main">
        {selectedPeer ? (
          <>
            <div className="chat-header">
              <h3>💬 Chat with {selectedPeer}</h3>
            </div>

            <div className="message-list">
              {messages.map(msg => (
                <div key={msg.id} className={`message ${msg.sent ? 'sent' : 'received'}`}>
                  <div className="content">{msg.content}</div>
                  <div className="time">
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              ))}
            </div>

            <div className="message-input">
              <input
                type="text"
                placeholder="Type a message..."
                value={message}
                onChange={e => setMessage(e.target.value)}
                onKeyPress={e => e.key === 'Enter' && sendMessage()}
              />
              <button className="primary" onClick={sendMessage}>
                Send 🔒
              </button>
            </div>

            <div className="decrypt-input">
              <input
                type="text"
                placeholder="Paste encrypted message (hex) to decrypt"
              />
              <button className="secondary" onClick={() => {
                const input = document.querySelector('.decrypt-input input') as HTMLInputElement
                if (input?.value) decryptMessage(input.value)
              }}>
                Decrypt
              </button>
            </div>
          </>
        ) : (
          <div className="no-chat">
            <h2>🔐 Secure Messaging</h2>
            <p>Select a session or create a new one to start chatting</p>
            <p className="hint">All messages are end-to-end encrypted</p>
          </div>
        )}
      </div>

      {status && (
        <div className="status-bar">
          <span>{status}</span>
        </div>
      )}
    </div>
  )
}
