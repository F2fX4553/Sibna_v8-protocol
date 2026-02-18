import { useState, useEffect } from 'react'
import { SibnaClient } from './utils/sibna'
import { ChatWindow } from './components/ChatWindow'
import { IdentityPanel } from './components/IdentityPanel'
import { GroupPanel } from './components/GroupPanel'
import './App.css'

function App() {
  const [client, setClient] = useState<SibnaClient | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<'chat' | 'groups' | 'identity'>('chat')
  const [selectedPeer, setSelectedPeer] = useState<string | null>(null)

  useEffect(() => {
    async function initClient() {
      try {
        const sibna = new SibnaClient()
        await sibna.init()
        setClient(sibna)
      } catch (e) {
        setError(`Failed to initialize: ${e}`)
      } finally {
        setLoading(false)
      }
    }
    initClient()
  }, [])

  if (loading) {
    return (
      <div className="loading">
        <div className="spinner"></div>
        <p>Loading Sibna Protocol...</p>
      </div>
    )
  }

  if (error) {
    return (
      <div className="error">
        <h2>Error</h2>
        <p>{error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    )
  }

  return (
    <div className="app">
      <header className="header">
        <h1>🔒 Sibna</h1>
        <span className="version">v7.0.0</span>
        {client && (
          <span className="device-id">Device: {client.getDeviceId()}</span>
        )}
      </header>

      <nav className="tabs">
        <button 
          className={activeTab === 'chat' ? 'active' : ''}
          onClick={() => setActiveTab('chat')}
        >
          💬 Chat
        </button>
        <button 
          className={activeTab === 'groups' ? 'active' : ''}
          onClick={() => setActiveTab('groups')}
        >
          👥 Groups
        </button>
        <button 
          className={activeTab === 'identity' ? 'active' : ''}
          onClick={() => setActiveTab('identity')}
        >
          🔑 Identity
        </button>
      </nav>

      <main className="content">
        {client && activeTab === 'chat' && (
          <ChatWindow 
            client={client} 
            selectedPeer={selectedPeer}
            onSelectPeer={setSelectedPeer}
          />
        )}
        {client && activeTab === 'groups' && (
          <GroupPanel client={client} />
        )}
        {client && activeTab === 'identity' && (
          <IdentityPanel client={client} />
        )}
      </main>

      <footer className="footer">
        <p>Sibna Protocol - End-to-End Encrypted Messaging</p>
      </footer>
    </div>
  )
}

export default App
