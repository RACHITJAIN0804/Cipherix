import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, ConfirmDialog } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Vault, Plus, Lock, Unlock, Key, Trash2, ArrowRight, X } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

export function VaultsView({ user, onLogout }) {
  const navigate = useNavigate();
  const [vaults, setVaults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  // Modals state
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [unlockModalOpen, setUnlockModalOpen] = useState(false);
  const [deleteVaultId, setDeleteVaultId] = useState(null);
  const [selectedVault, setSelectedVault] = useState(null);

  // Form states
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

  useEffect(() => {
    fetchVaults();
  }, []);

  const handleCreateVault = async (e) => {
    e.preventDefault();
    if (!name.trim() || !password.trim()) {
      alert('Please provide both name and password.');
      return;
    }
    try {
      const res = await CipherixAPI.request('/vaults', {
        method: 'POST',
        body: JSON.stringify({ name, password }),
      });
      if (res.seed) {
        setCreatedSeed(res.seed);
      } else {
        setCreateModalOpen(false);
      }
      setName('');
      setPassword('');
      fetchVaults();
    } catch (err) {
      alert('Create Vault Error: ' + err.message);
    }
  };

  const handleUnlockVault = async (e) => {
    e.preventDefault();
    if (!selectedVault || !unlockPassword) return;
    try {
      await CipherixAPI.request(`/vaults/${selectedVault.vault_id}/unlock`, {
        method: 'POST',
        body: JSON.stringify({ password: unlockPassword }),
      });
      setUnlockModalOpen(false);
      setUnlockPassword('');
      fetchVaults();
    } catch (err) {
      alert('Unlock Error: ' + err.message);
    }
  };

  const handleLockVault = async (vaultId) => {
    try {
      await CipherixAPI.request(`/vaults/${vaultId}/lock`, { method: 'POST' });
      fetchVaults();
    } catch (err) {
      alert('Lock Error: ' + err.message);
    }
  };

  const handleDeleteVault = async () => {
    if (!deleteVaultId) return;
    try {
      await CipherixAPI.request(`/vaults/${deleteVaultId}`, { method: 'DELETE' });
      setDeleteVaultId(null);
      fetchVaults();
    } catch (err) {
      alert('Delete Error: ' + err.message);
    }
  };

  return (
    <PageLayout title="Encrypted Vaults" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={Vault}
        iconColor="text-cyan-400"
        title="Encrypted Vault Management"
        description="Vaults isolate encrypted files, vector embeddings, and RAG context using Argon2id key derivation."
      >
        <button
          onClick={() => { setCreatedSeed(''); setCreateModalOpen(true); }}
          className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 text-black font-bold text-xs flex items-center gap-2 hover:opacity-90 transition-opacity shadow-lg shadow-cyan-500/20"
        >
          <Plus className="w-4 h-4" />
          <span>Create New Vault</span>
        </button>
      </PageHeader>

      {error && <ErrorState message={error} onRetry={fetchVaults} />}

      {loading ? (
        <LoadingState message="Fetching user vaults..." />
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
            <div key={v.vault_id} className="glass-panel p-6 flex flex-col gap-4 border-cyan-500/20">
              {/* Vault Header */}
              <div className="flex justify-between items-start">
                <div className="w-11 h-11 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0">
                  <Vault className="w-6 h-6" />
                </div>
                <div className="flex items-center gap-2">
                  <span className={`badge-tag ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}`}>
                    {v.status === 'unlocked' ? <Unlock className="w-3 h-3 mr-1" /> : <Lock className="w-3 h-3 mr-1" />}
                    {v.status.toUpperCase()}
                  </span>
                  <button
                    onClick={() => setDeleteVaultId(v.vault_id)}
                    className="p-1.5 rounded-lg text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 transition-colors"
                    title="Delete Vault"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>

              {/* Vault Info */}
              <div className="flex-1">
                <h3 className="text-base font-bold font-outfit text-slate-100">{v.name}</h3>
                <div className="text-xs text-slate-400 font-mono mt-1 truncate">ID: {v.vault_id}</div>
              </div>

              {/* Vault Metadata */}
              <div className="text-xs flex flex-col gap-1.5 text-slate-400 pt-3 border-t border-slate-800/80">
                <div className="flex justify-between">
                  <span>Key Derivation:</span>
                  <span className="text-emerald-400 font-semibold">Argon2id (m=64MB)</span>
                </div>
                <div className="flex justify-between">
                  <span>Cipher Algorithm:</span>
                  <span className="text-purple-400 font-semibold">AES-256-GCM</span>
                </div>
              </div>

              {/* Vault Actions */}
              <div className="flex gap-2 pt-1">
                {v.status === 'unlocked' ? (
                  <>
                    <button
                      onClick={() => navigate('/documents')}
                      className="flex-1 py-2 px-3 rounded-xl bg-cyan-500 text-black text-xs font-bold flex items-center justify-center gap-1.5 hover:bg-cyan-400 transition-colors"
                    >
                      <span>Open Documents</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </button>
                    <button
                      onClick={() => handleLockVault(v.vault_id)}
                      className="py-2 px-3 rounded-xl bg-slate-900 border border-slate-800 text-xs font-semibold text-amber-400 hover:border-amber-500/40 transition-colors"
                    >
                      Lock
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => { setSelectedVault(v); setUnlockModalOpen(true); }}
                    className="w-full py-2 px-3 rounded-xl bg-slate-900 border border-slate-800 text-xs font-bold text-slate-200 hover:border-cyan-500/40 transition-colors"
                  >
                    Unlock Vault
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Vault Modal */}
      {createModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel max-w-md w-full p-6 flex flex-col gap-4 relative border-slate-800">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold font-outfit text-slate-100">Create Encrypted Vault</h3>
              <button
                onClick={() => setCreateModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {createdSeed ? (
              <div className="flex flex-col gap-4 text-xs">
                <div className="p-3 rounded-xl bg-amber-500/10 border border-amber-500/40 text-amber-300">
                  <strong>Important!</strong> Your vault has been created. Below is your 16-word BIP-39 recovery seed. Store it offline safely. It will NOT be shown again.
                </div>
                <div className="font-mono text-cyan-400 p-3 bg-black rounded-xl border border-slate-800 leading-relaxed select-all">
                  {createdSeed}
                </div>
                <button
                  onClick={() => setCreateModalOpen(false)}
                  className="w-full py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-xs hover:bg-cyan-400 transition-colors"
                >
                  I Have Saved My Seed
                </button>
              </div>
            ) : (
              <form onSubmit={handleCreateVault} className="flex flex-col gap-4">
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-400 mb-1.5">Vault Name</label>
                  <input
                    type="text"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    placeholder="e.g. Financial Security Vault"
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-400 mb-1.5">Vault Unlock Password</label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Strong password..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
                <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                  <button
                    type="button"
                    onClick={() => setCreateModalOpen(false)}
                    className="px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-xl bg-cyan-500 text-black text-xs font-bold hover:bg-cyan-400 transition-colors"
                  >
                    Create Vault
                  </button>
                </div>
              </form>
            )}
          </div>
        </div>
      )}

      {/* Unlock Vault Modal */}
      {unlockModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="glass-panel max-w-sm w-full p-6 flex flex-col gap-4 relative border-slate-800">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold font-outfit text-slate-100">Unlock {selectedVault?.name}</h3>
              <button
                onClick={() => setUnlockModalOpen(false)}
                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleUnlockVault} className="flex flex-col gap-4">
              <div>
                <label className="block text-xs font-bold uppercase text-slate-400 mb-1.5">Vault Password</label>
                <input
                  type="password"
                  value={unlockPassword}
                  onChange={(e) => setUnlockPassword(e.target.value)}
                  placeholder="Enter vault password..."
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setUnlockModalOpen(false)}
                  className="px-4 py-2 rounded-xl bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:bg-slate-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl bg-cyan-500 text-black text-xs font-bold hover:bg-cyan-400 transition-colors"
                >
                  Unlock
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation */}
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
