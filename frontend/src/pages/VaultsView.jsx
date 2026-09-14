import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, ConfirmDialog } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Vault, Plus, Lock, Unlock, Trash2, ArrowRight, X, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export function VaultsView({ user, onLogout }) {
  const navigate = useNavigate();
  const [vaults, setVaults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [unlockModalOpen, setUnlockModalOpen] = useState(false);
  const [deleteVaultId, setDeleteVaultId] = useState(null);
  const [selectedVault, setSelectedVault] = useState(null);

  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [unlockPassword, setUnlockPassword] = useState('');
  const [createdSeed, setCreatedSeed] = useState('');

  const fetchVaults = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await CipherixAPI.request('/vaults');
      setVaults(Array.isArray(data) ? data : []);
    } catch (err) {
      setError('Failed to load vaults: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchVaults(); }, []);

  const handleCreateVault = async (e) => {
    e.preventDefault();
    if (!name.trim() || !password.trim()) { alert('Please provide both name and password.'); return; }
    try {
      const res = await CipherixAPI.request('/vaults', {
        method: 'POST',
        body: JSON.stringify({ name, password }),
      });
      if (res.seed) { setCreatedSeed(res.seed); } else { setCreateModalOpen(false); }
      setName(''); setPassword('');
      fetchVaults();
    } catch (err) { alert('Create Vault Error: ' + err.message); }
  };

  const handleUnlockVault = async (e) => {
    e.preventDefault();
    if (!selectedVault || !unlockPassword) return;
    try {
      await CipherixAPI.request(`/vaults/${selectedVault.vault_id}/unlock`, {
        method: 'POST',
        body: JSON.stringify({ password: unlockPassword }),
      });
      setUnlockModalOpen(false); setUnlockPassword(''); fetchVaults();
    } catch (err) { alert('Unlock Error: ' + err.message); }
  };

  const handleLockVault = async (vaultId) => {
    try {
      await CipherixAPI.request(`/vaults/${vaultId}/lock`, { method: 'POST' });
      fetchVaults();
    } catch (err) { alert('Lock Error: ' + err.message); }
  };

  const handleDeleteVault = async () => {
    if (!deleteVaultId) return;
    try {
      await CipherixAPI.request(`/vaults/${deleteVaultId}`, { method: 'DELETE' });
      setDeleteVaultId(null); fetchVaults();
    } catch (err) { alert('Delete Error: ' + err.message); }
  };

  
  const inputStyle = {
    width: '100%',
    background: 'var(--bg-input)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '10px',
    padding: '10px 14px',
    fontSize: '0.8125rem',
    color: 'var(--text-primary)',
    outline: 'none',
    transition: 'border-color 160ms ease, box-shadow 160ms ease',
    boxSizing: 'border-box',
    fontFamily: 'inherit',
  };

  return (
    <PageLayout title="Encrypted Vaults" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={Vault}
        iconColor="text-cyan-400"
        title="Encrypted Vault Management"
        description="Vaults isolate encrypted files, vector embeddings, and RAG context using Argon2id key derivation."
      >
        <button
          onClick={() => { setCreatedSeed(''); setCreateModalOpen(true); }}
          className="btn btn-primary"
        >
          <Plus style={{ width: 15, height: 15 }} />
          <span>Create New Vault</span>
        </button>
      </PageHeader>

      {error && <ErrorState message={error} onRetry={fetchVaults} />}

      {loading ? (
        <LoadingState message="Fetching encrypted vaults..." />
      ) : vaults.length === 0 ? (
        <EmptyState
          title="No Vaults Found"
          description="Create your first Argon2id encrypted vault to start storing documents securely."
          actionLabel="Create Vault"
          onAction={() => setCreateModalOpen(true)}
        />
      ) : (
        <div className="cards-grid">
          {vaults.map((v) => (
            <div
              key={v.vault_id}
              className="glass-panel"
              style={{ padding: '22px', display: 'flex', flexDirection: 'column', gap: '16px' }}
            >
              {}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div
                  style={{
                    width: 44,
                    height: 44,
                    borderRadius: '13px',
                    background: 'rgba(34,211,238,0.09)',
                    border: '1px solid rgba(34,211,238,0.22)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <Vault style={{ width: 22, height: 22, color: 'var(--accent-cyan)' }} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span className={`badge-tag ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}`}>
                    {v.status === 'unlocked'
                      ? <Unlock style={{ width: 10, height: 10 }} />
                      : <Lock style={{ width: 10, height: 10 }} />
                    }
                    {v.status.toUpperCase()}
                  </span>
                  <button
                    onClick={() => setDeleteVaultId(v.vault_id)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      width: 30,
                      height: 30,
                      borderRadius: '8px',
                      background: 'transparent',
                      border: 'none',
                      color: 'var(--text-muted)',
                      cursor: 'pointer',
                      transition: 'all 160ms',
                    }}
                    title="Delete Vault"
                    onMouseEnter={e => {
                      e.currentTarget.style.background = 'rgba(239,68,68,0.10)';
                      e.currentTarget.style.color = '#f87171';
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.background = 'transparent';
                      e.currentTarget.style.color = 'var(--text-muted)';
                    }}
                  >
                    <Trash2 style={{ width: 14, height: 14 }} />
                  </button>
                </div>
              </div>

              {}
              <div style={{ flex: 1 }}>
                <h3
                  style={{
                    fontSize: '0.9375rem',
                    fontWeight: 700,
                    fontFamily: "'Outfit', sans-serif",
                    color: 'var(--text-primary)',
                    margin: '0 0 4px 0',
                  }}
                >
                  {v.name}
                </h3>
                <div
                  style={{
                    fontSize: '0.6875rem',
                    color: 'var(--text-muted)',
                    fontFamily: "'JetBrains Mono', monospace",
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {v.vault_id}
                </div>
              </div>

              {}
              <div
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '6px',
                  fontSize: '0.78125rem',
                  color: 'var(--text-secondary)',
                  paddingTop: '12px',
                  borderTop: '1px solid rgba(255,255,255,0.06)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Key Derivation</span>
                  <span style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>Argon2id (m=64MB)</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>Cipher</span>
                  <span style={{ color: 'var(--accent-purple)', fontWeight: 600 }}>AES-256-GCM</span>
                </div>
              </div>

              {}
              <div style={{ display: 'flex', gap: '8px' }}>
                {v.status === 'unlocked' ? (
                  <>
                    <button
                      onClick={() => navigate('/documents')}
                      className="btn btn-primary"
                      style={{ flex: 1, fontSize: '0.8rem' }}
                    >
                      <span>Open Documents</span>
                      <ArrowRight style={{ width: 13, height: 13 }} />
                    </button>
                    <button
                      onClick={() => handleLockVault(v.vault_id)}
                      className="btn btn-secondary"
                      style={{ fontSize: '0.8rem', color: 'var(--accent-amber)' }}
                    >
                      Lock
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => { setSelectedVault(v); setUnlockModalOpen(true); }}
                    className="btn btn-secondary"
                    style={{ flex: 1, fontSize: '0.8rem' }}
                  >
                    <Unlock style={{ width: 13, height: 13 }} />
                    Unlock Vault
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {}
      {createModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-panel" style={{ maxWidth: '440px' }}>
            <div className="modal-header">
              <h3 className="modal-title">Create Encrypted Vault</h3>
              <button
                onClick={() => setCreateModalOpen(false)}
                style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: 'transparent', border: 'none',
                  color: 'var(--text-muted)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 160ms',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--text-primary)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)'; }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            {createdSeed ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div
                  style={{
                    padding: '12px 16px',
                    borderRadius: '10px',
                    background: 'rgba(245,158,11,0.08)',
                    border: '1px solid rgba(245,158,11,0.30)',
                    color: '#fcd34d',
                    fontSize: '0.8rem',
                    lineHeight: 1.6,
                  }}
                >
                  <strong>Important!</strong> Your vault has been created. Below is your 16-word BIP-39 recovery seed.
                  Store it offline safely. It will <strong>NOT</strong> be shown again.
                </div>
                <div
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '0.8125rem',
                    color: 'var(--accent-cyan)',
                    padding: '14px 16px',
                    background: 'rgba(0,0,0,0.40)',
                    borderRadius: '10px',
                    border: '1px solid rgba(255,255,255,0.07)',
                    lineHeight: 1.7,
                    wordBreak: 'break-word',
                    userSelect: 'all',
                  }}
                >
                  {createdSeed}
                </div>
                <button onClick={() => setCreateModalOpen(false)} className="btn btn-primary" style={{ width: '100%' }}>
                  <ShieldCheck style={{ width: 14, height: 14 }} />
                  I Have Saved My Seed
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreateVault} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div>
                  <label className="form-label">Vault Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Financial Security Vault"
                    style={inputStyle}
                    onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                    onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                  />
                </div>
                <div>
                  <label className="form-label">Vault Unlock Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Strong password..."
                    style={inputStyle}
                    onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                    onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                  />
                </div>
                <div className="modal-footer" style={{ paddingTop: 0, marginTop: 0, border: 'none' }}>
                  <button type="button" onClick={() => setCreateModalOpen(false)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>Cancel</button>
                  <button type="submit" className="btn btn-primary" style={{ fontSize: '0.8rem' }}>Create Vault</button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {}
      {unlockModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-panel" style={{ maxWidth: '380px' }}>
            <div className="modal-header">
              <h3 className="modal-title">Unlock {selectedVault?.name}</h3>
              <button
                onClick={() => setUnlockModalOpen(false)}
                style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: 'transparent', border: 'none',
                  color: 'var(--text-muted)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 160ms',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--text-primary)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)'; }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>
            <form onSubmit={handleUnlockVault} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div>
                <label className="form-label">Vault Password</label>
                <input
                  type="password"
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  placeholder="Enter vault password..."
                  style={inputStyle}
                  onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                  autoFocus
                />
              </div>
              <div className="modal-footer" style={{ paddingTop: 0, marginTop: 0, border: 'none' }}>
                <button type="button" onClick={() => setUnlockModalOpen(false)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>Cancel</button>
                <button type="submit" className="btn btn-primary" style={{ fontSize: '0.8rem' }}>
                  <Unlock style={{ width: 13, height: 13 }} />
                  Unlock
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {}
      <ConfirmDialog
        isOpen={!!deleteVaultId}
        title="Delete Encrypted Vault"
        message="Are you sure you want to permanently delete this vault and all its encrypted documents and vector embeddings? This operation cannot be undone."
        confirmLabel="Delete Vault"
        onConfirm={handleDeleteVault}
        onCancel={() => setDeleteVaultId(null)}
      />
    </PageLayout>
  );
}
