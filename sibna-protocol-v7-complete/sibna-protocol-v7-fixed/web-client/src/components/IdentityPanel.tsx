import { useState } from 'react'

interface IdentityPanelProps {
  client: any
}

export function IdentityPanel({ client }: IdentityPanelProps) {
  const [identity, setIdentity] = useState<any>(null)
  const [copied, setCopied] = useState<string | null>(null)

  async function generateIdentity() {
    const id = await client.generateIdentity()
    setIdentity(id)
  }

  function copyToClipboard(text: string, field: string) {
    navigator.clipboard.writeText(text)
    setCopied(field)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="identity-panel">
      <h2>🔑 Identity Keys</h2>
      
      <div className="card">
        <p className="info">
          Your identity keys are used for secure communication. 
          Never share your private key!
        </p>

        {!identity ? (
          <button className="primary" onClick={generateIdentity}>
            Generate New Identity
          </button>
        ) : (
          <div className="keys">
            <div className="key-section">
              <h4>🔓 X25519 Public Key</h4>
              <p className="key-value">{identity.x25519_public}</p>
              <button 
                className="secondary small"
                onClick={() => copyToClipboard(identity.x25519_public, 'x25519')}
              >
                {copied === 'x25519' ? '✓ Copied!' : 'Copy'}
              </button>
            </div>

            <div className="key-section">
              <h4>🔐 Ed25519 Public Key</h4>
              <p className="key-value">{identity.ed25519_public}</p>
              <button 
                className="secondary small"
                onClick={() => copyToClipboard(identity.ed25519_public, 'ed25519')}
              >
                {copied === 'ed25519' ? '✓ Copied!' : 'Copy'}
              </button>
            </div>

            <div className="key-section warning">
              <h4>⚠️ Private Seed (KEEP SECRET!)</h4>
              <p className="key-value blurred">{identity.private_seed}</p>
              <button 
                className="secondary small"
                onClick={() => copyToClipboard(identity.private_seed, 'private')}
              >
                {copied === 'private' ? '✓ Copied!' : 'Copy'}
              </button>
            </div>

            <button className="primary" onClick={generateIdentity}>
              Regenerate Identity
            </button>
          </div>
        )}
      </div>

      <div className="card">
        <h3>📋 Device Information</h3>
        <div className="device-info">
          <div className="info-row">
            <span>Device ID:</span>
            <code>{client.getDeviceId()}</code>
          </div>
          <div className="info-row">
            <span>Protocol Version:</span>
            <code>7.0.0</code>
          </div>
          <div className="info-row">
            <span>Encryption:</span>
            <code>ChaCha20-Poly1305</code>
          </div>
          <div className="info-row">
            <span>Key Exchange:</span>
            <code>X3DH + X25519</code>
          </div>
          <div className="info-row">
            <span>Signatures:</span>
            <code>Ed25519</code>
          </div>
        </div>
      </div>
    </div>
  )
}
