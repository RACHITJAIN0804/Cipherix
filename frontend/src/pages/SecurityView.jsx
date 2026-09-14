import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { KeyRound, RefreshCw, ShieldCheck, Lock } from 'lucide-react';

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
        if (vList.length > 0 && !selectedVaultId) setSelectedVaultId(vList[0].vault_id);
      } catch (err) { console.warn(err); }
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
      setSuccessMsg('Vault password changed successfully! Master Key re-derived and Vault Key re-encrypted.');
      setOldPassword(''); setNewPassword('');
    } catch (err) {
      setError('Password Change Error: ' + err.message);
    } finally {
      setLoading(false);
    }
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
    <PageLayout title="Security & Keys" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={KeyRound}
        iconColor="text-rose-400"
        title="Cryptographic Policy & Password Rewrapping"
        description="Manage vault key lifecycle — re-derive Argon2id master keys and re-encrypt vault keys without re-encrypting document blobs."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
      </PageHeader>

      {}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', borderColor: 'rgba(239,68,68,0.15)' }}>
        <div>
          <h3 className="section-title" style={{ marginBottom: '6px' }}>
            <Lock style={{ width: 16, height: 16, color: '#f87171' }} />
            Vault Key Rewrapping
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
            Re-derives the Master Key via Argon2id and re-encrypts the internal Vault Key without re-encrypting document blobs.
          </p>
        </div>

        {error && <ErrorState message={error} />}
        {successMsg && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '12px 16px',
              borderRadius: '10px',
              background: 'rgba(16,185,129,0.08)',
              border: '1px solid rgba(16,185,129,0.28)',
              color: '#6ee7b7',
              fontSize: '0.8125rem',
              fontWeight: 600,
            }}
          >
            <ShieldCheck style={{ width: 16, height: 16, flexShrink: 0 }} />
            {successMsg}
          </div>
        )}

        <form onSubmit={handleChangePassword} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
            <div>
              <label className="form-label">Current Vault Password</label>
              <input
                type="password"
                value={oldPassword}
                onChange={(e) => setOldPassword(e.target.value)}
                placeholder="Enter current password..."
                style={inputStyle}
                onFocus={e => { e.target.style.borderColor = 'rgba(239,68,68,0.40)'; e.target.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.07)'; }}
                onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
              />
            </div>
            <div>
              <label className="form-label">New Vault Password</label>
              <input
                type="password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                placeholder="Enter strong new password..."
                style={inputStyle}
                onFocus={e => { e.target.style.borderColor = 'rgba(239,68,68,0.40)'; e.target.style.boxShadow = '0 0 0 3px rgba(239,68,68,0.07)'; }}
                onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
              />
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              disabled={loading}
              className="btn btn-danger"
            >
              <RefreshCw style={{ width: 14, height: 14, ...(loading ? { animation: 'spin 1s linear infinite' } : {}) }} />
              Rewrap Vault Key
            </button>
          </div>
        </form>
      </div>

      {}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 className="section-title">
          <ShieldCheck style={{ width: 16, height: 16, color: 'var(--accent-emerald)' }} />
          Cryptographic Parameters
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
          {[
            {
              label: 'Argon2id KDF Settings',
              value: 'm=65536KB, t=3, p=4',
              valueColor: 'var(--accent-emerald)',
              note: 'OWASP High-Security Compliant',
            },
            {
              label: 'Symmetric Encryption',
              value: 'AES-256-GCM',
              valueColor: 'var(--accent-purple)',
              note: '96-bit CSPRNG Nonce + 128-bit Auth Tag',
            },
          ].map(({ label, value, valueColor, note }) => (
            <div
              key={label}
              style={{
                padding: '16px 18px',
                borderRadius: '11px',
                background: 'rgba(7,10,18,0.50)',
                border: '1px solid rgba(255,255,255,0.07)',
              }}
            >
              <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '6px' }}>{label}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.9rem', fontWeight: 700, color: valueColor }}>{value}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '4px' }}>{note}</div>
            </div>
          ))}
        </div>
      </div>
    </PageLayout>
  );
}
