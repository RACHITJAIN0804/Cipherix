import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { KeyRound, RefreshCw } from 'lucide-react';

export function SecurityView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    async function loadVaults() {
      try {
        const data = await CipherixAPI.request('/vaults');
        const vList = Array.isArray(data) ? data : [];
        setVaults(vList);
        if (vList.length > 0 && !selectedVaultId) {
          setSelectedVaultId(vList[0].vault_id);
        }
      } catch (err) {
        console.warn(err);
      }
    }
    loadVaults();
  }, []);

  const handleChangePassword = async (e) => {
    e.preventDefault();
    if (!selectedVaultId || !oldPassword || !newPassword) {
      alert('Please fill in all fields.');
      return;
    }

    setLoading(true);
    setError('');
    setSuccessMsg('');
    try {
      await CipherixAPI.request(`/vaults/${selectedVaultId}/change-password`, {
        method: 'POST',
        body: JSON.stringify({ old_password: oldPassword, new_password: newPassword }),
      });
      setSuccessMsg(
        'Vault password changed successfully! Master Key re-derived and Vault Key re-encrypted.'
      );
      setOldPassword('');
      setNewPassword('');
    } catch (err) {
      setError('Password Change Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageLayout title="Security & Keys" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={KeyRound}
        iconColor="text-rose-400"
        title="Cryptographic Policy & Password Rewrapping"
        description="Manage vault key lifecycle — re-derive Argon2id master keys and re-encrypt vault keys without re-encrypting document blobs."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
      </PageHeader>

      {/* Main Security Panel */}
      <div className="glass-panel p-6 flex flex-col gap-6 border-rose-500/20">
        {/* Change Password Form */}
        <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-4">
          <div>
            <h3 className="text-sm font-bold font-outfit text-slate-100">
              Vault Key Rewrapping (Change Password)
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Re-derives the Master Key via Argon2id and re-encrypts the internal Vault Key without
              re-encrypting document blobs.
            </p>
          </div>

          {error && <ErrorState message={error} />}
          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs font-semibold">
              {successMsg}
            </div>
          )}

          <form onSubmit={handleChangePassword} className="flex flex-col gap-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-xs font-bold uppercase text-slate-400 mb-1.5">
                  Current Vault Password
                </label>
                <input
                  type="password"
                  value={oldPassword}
                  onChange={(e) => setOldPassword(e.target.value)}
                  placeholder="Enter current password..."
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-rose-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase text-slate-400 mb-1.5">
                  New Vault Password
                </label>
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter strong new password..."
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-rose-500 transition-colors"
                />
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={loading}
                className="px-5 py-2.5 rounded-xl bg-rose-500 text-black font-bold text-xs flex items-center gap-2 hover:bg-rose-400 transition-colors disabled:opacity-60"
              >
                <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                <span>Rewrap Vault Key</span>
              </button>
            </div>
          </form>
        </div>

        {/* Cryptographic Info Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold">Argon2id KDF Settings</div>
            <div className="text-emerald-400 font-mono font-bold">m=65536KB, t=3, p=4</div>
            <div className="text-slate-400 text-[10px]">OWASP High-Security Compliant</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold">Symmetric Key Encryption</div>
            <div className="text-purple-400 font-mono font-bold">AES-256-GCM</div>
            <div className="text-slate-400 text-[10px]">96-bit CSPRNG Nonce + 128-bit Auth Tag</div>
          </div>
        </div>
      </div>
    </PageLayout>
  );
}
