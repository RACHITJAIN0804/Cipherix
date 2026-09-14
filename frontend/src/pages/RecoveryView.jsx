import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { LifeBuoy, Sparkles, Check, KeyRound, Copy, ShieldCheck } from 'lucide-react';

export function RecoveryView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [generatedSeed, setGeneratedSeed] = useState('');
  const [copied, setCopied] = useState(false);
  const [recoverySeed, setRecoverySeed] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [recoverySuccess, setRecoverySuccess] = useState('');
  const [loading, setLoading] = useState(false);
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

  const handleGenerateSeed = async () => {
    if (!selectedVaultId) return;
    setLoading(true); setError('');
    try {
      const res = await CipherixAPI.request(`/vaults/${selectedVaultId}/recovery-seed`, { method: 'POST' });
      setGeneratedSeed(res.seed || '');
    } catch (err) { setError('Seed Generation Error: ' + err.message); }
    finally { setLoading(false); }
  };

  const handleRecoverVault = async (e) => {
    e.preventDefault();
    if (!selectedVaultId || !recoverySeed.trim() || !newPassword.trim()) {
      alert('Please provide both recovery seed and new password.');
      return;
    }
    setLoading(true); setError(''); setRecoverySuccess('');
    try {
      await CipherixAPI.request(`/vaults/${selectedVaultId}/recover`, {
        method: 'POST',
        body: JSON.stringify({ recovery_seed: recoverySeed.trim(), new_password: newPassword.trim() }),
      });
      setRecoverySuccess('Vault successfully recovered! Password updated and Master Key re-wrapped.');
      setRecoverySeed(''); setNewPassword('');
    } catch (err) { setError('Vault Recovery Error: ' + err.message); }
    finally { setLoading(false); }
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
    <PageLayout title="BIP-39 Vault Recovery" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={LifeBuoy}
        iconColor="text-purple-400"
        title="BIP-39 Vault Recovery Workflow"
        description="16-word mnemonic seeds allow emergency recovery of locked vaults even if passwords are lost."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
      </PageHeader>

      {error && <ErrorState message={error} />}
      {recoverySuccess && (
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
          {recoverySuccess}
        </div>
      )}

      {}
      <div
        className="glass-panel"
        style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', borderColor: 'rgba(168,85,247,0.15)' }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '16px' }}>
          <div>
            <h3 className="section-title" style={{ marginBottom: '6px' }}>
              <Sparkles style={{ width: 15, height: 15, color: 'var(--accent-purple)' }} />
              1. Generate Recovery Seed
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
              Generates a BIP-39 mnemonic seed. Displayed once — store offline safely.
            </p>
          </div>
          <button
            onClick={handleGenerateSeed}
            disabled={loading}
            className="btn"
            style={{
              background: 'var(--accent-purple)',
              color: '#050a12',
              flexShrink: 0,
              boxShadow: '0 4px 14px rgba(168,85,247,0.20)',
            }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = '#c084fc'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-purple)'; e.currentTarget.style.transform = 'translateY(0)'; }}
          >
            <Sparkles style={{ width: 14, height: 14 }} />
            Generate Seed
          </button>
        </div>

        {generatedSeed && (
          <div
            style={{
              padding: '16px',
              borderRadius: '10px',
              background: 'rgba(0,0,0,0.40)',
              border: '1px solid rgba(168,85,247,0.20)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.6875rem',
                  color: 'var(--accent-purple)',
                  fontWeight: 700,
                  letterSpacing: '0.06em',
                  textTransform: 'uppercase',
                }}
              >
                16-Word Recovery Mnemonic
              </span>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedSeed);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 2000);
                }}
                className="btn btn-ghost"
                style={{ padding: '4px 10px', fontSize: '0.75rem', gap: '5px' }}
              >
                {copied ? <Check style={{ width: 12, height: 12, color: 'var(--accent-emerald)' }} /> : <Copy style={{ width: 12, height: 12 }} />}
                {copied ? 'Copied!' : 'Copy'}
              </button>
            </div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.8125rem',
                color: 'var(--accent-cyan)',
                lineHeight: 1.8,
                wordBreak: 'break-word',
                userSelect: 'all',
                padding: '12px',
                background: 'rgba(0,0,0,0.30)',
                borderRadius: '8px',
              }}
            >
              {generatedSeed}
            </div>
          </div>
        )}
      </div>

      {}
      <div
        className="glass-panel"
        style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px', borderColor: 'rgba(168,85,247,0.15)' }}
      >
        <div>
          <h3 className="section-title" style={{ marginBottom: '6px' }}>
            <KeyRound style={{ width: 15, height: 15, color: 'var(--accent-cyan)' }} />
            2. Emergency Vault Recovery
          </h3>
          <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
            Enter your 16-word BIP-39 recovery seed to unlock a locked vault and rewrap with a new password.
          </p>
        </div>

        <form onSubmit={handleRecoverVault} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <label className="form-label">16-Word BIP-39 Recovery Seed</label>
            <textarea
              value={recoverySeed}
              onChange={(e) => setRecoverySeed(e.target.value)}
              placeholder="e.g. alpha bravo cipher delta echo foxtrot golf hotel..."
              rows={3}
              style={{
                ...inputStyle,
                fontFamily: "'JetBrains Mono', 'Courier New', monospace",
                color: 'var(--accent-cyan)',
                resize: 'vertical',
                minHeight: '72px',
              }}
              onFocus={e => { e.target.style.borderColor = 'rgba(168,85,247,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.07)'; }}
              onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
            />
          </div>
          <div>
            <label className="form-label">New Vault Password</label>
            <input
              type="password"
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              placeholder="Enter new vault password..."
              style={inputStyle}
              onFocus={e => { e.target.style.borderColor = 'rgba(168,85,247,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.07)'; }}
              onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
            >
              <KeyRound style={{ width: 14, height: 14 }} />
              Recover Vault & Reset Password
            </button>
          </div>
        </form>
      </div>
    </PageLayout>
  );
}
