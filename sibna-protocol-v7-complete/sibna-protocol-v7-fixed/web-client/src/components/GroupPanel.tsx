import { useState } from 'react'

interface GroupPanelProps {
  client: any
}

export function GroupPanel({ client }: GroupPanelProps) {
  const [groupId, setGroupId] = useState('')
  const [groups, setGroups] = useState<string[]>([])
  const [selectedGroup, setSelectedGroup] = useState<string | null>(null)
  const [memberKey, setMemberKey] = useState('')
  const [message, setMessage] = useState('')
  const [status, setStatus] = useState('')

  async function createGroup() {
    if (!groupId.trim()) {
      // Generate random group ID
      const randomId = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0'))
        .join('')
      setGroupId(randomId)
      return
    }

    try {
      setStatus('Creating group...')
      await client.createGroup(groupId)
      await loadGroups()
      setSelectedGroup(groupId)
      setStatus('Group created!')
      setGroupId('')
    } catch (e) {
      setStatus(`Error: ${e}`)
    }
  }

  async function loadGroups() {
    const groupList = await client.listGroups()
    setGroups(groupList)
  }

  async function addMember() {
    if (!selectedGroup || !memberKey.trim()) return

    try {
      await client.addGroupMember(selectedGroup, memberKey)
      setStatus('Member added!')
      setMemberKey('')
    } catch (e) {
      setStatus(`Error: ${e}`)
    }
  }

  async function sendGroupMessage() {
    if (!selectedGroup || !message.trim()) return

    try {
      const encrypted = await client.encryptGroup(selectedGroup, message)
      setStatus('Group message encrypted!')
      setMessage('')
      console.log('Encrypted message:', encrypted)
    } catch (e) {
      setStatus(`Error: ${e}`)
    }
  }

  return (
    <div className="group-panel">
      <h2>👥 Group Messaging</h2>

      <div className="card">
        <h3>Create Group</h3>
        <div className="create-group">
          <input
            type="text"
            placeholder="Group ID (leave empty for random)"
            value={groupId}
            onChange={e => setGroupId(e.target.value)}
          />
          <button className="primary" onClick={createGroup}>
            Create Group
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Your Groups</h3>
        {groups.length === 0 ? (
          <p className="empty">No groups yet. Create one above!</p>
        ) : (
          <div className="group-list">
            {groups.map(g => (
              <div
                key={g}
                className={`group-item ${selectedGroup === g ? 'active' : ''}`}
                onClick={() => setSelectedGroup(g)}
              >
                <span className="group-icon">👥</span>
                <code className="group-id">{g.substring(0, 16)}...</code>
              </div>
            ))}
          </div>
        )}
      </div>

      {selectedGroup && (
        <div className="card">
          <h3>Group: {selectedGroup.substring(0, 16)}...</h3>
          
          <div className="add-member">
            <h4>Add Member</h4>
            <input
              type="text"
              placeholder="Member's public key (hex)"
              value={memberKey}
              onChange={e => setMemberKey(e.target.value)}
            />
            <button className="secondary" onClick={addMember}>
              Add Member
            </button>
          </div>

          <div className="group-message">
            <h4>Send Message</h4>
            <textarea
              placeholder="Type your message..."
              value={message}
              onChange={e => setMessage(e.target.value)}
            />
            <button className="primary" onClick={sendGroupMessage}>
              Send to Group 🔒
            </button>
          </div>
        </div>
      )}

      {status && (
        <div className="status-bar">
          <span>{status}</span>
        </div>
      )}
    </div>
  )
}
