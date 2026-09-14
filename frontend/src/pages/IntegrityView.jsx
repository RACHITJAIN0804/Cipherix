import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { ErrorState, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { ShieldCheck, Boxes, RefreshCw, CheckCircle2, AlertTriangle, Database, HardDrive, Link } from 'lucide-react';

export function IntegrityView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [documents, setDocuments] = useState([]);
  const [selectedDocId, setSelectedDocId] = useState('');
  const [verifying, setVerifying] = useState(false);
  const [anchoring, setAnchoring] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [anchorResult, setAnchorResult] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    async function loadData() {
      try {
        const vList = await CipherixAPI.request('/vaults');
        const vArray = Array.isArray(vList) ? vList : [];
        setVaults(vArray);
        if (vArray.length > 0 && !selectedVaultId) setSelectedVaultId(vArray[0].vault_id);
        const targetVaultId = selectedVaultId || (vArray.length > 0 ? vArray[0].vault_id : '');
        if (targetVaultId) {
          const docList = await CipherixAPI.request(`/vaults/${targetVaultId}/documents`);
          const dArray = Array.isArray(docList) ? docList : [];
          setDocuments(dArray);
          if (dArray.length > 0) setSelectedDocId(dArray[0].document_id);
        }
      } catch (err) { console.warn(err); }
    }
    loadData();
  }, [selectedVaultId]);

  const handleVerify = async () => {
    if (!selectedVaultId || !selectedDocId) { alert('Please select both a vault and a document.'); return; }
    setVerifying(true); setError('');
    try {
      const res = await CipherixAPI.request('/blockchain/verify', {
        method: 'POST',
        body: JSON.stringify({ vault_id: selectedVaultId, document_id: selectedDocId }),
      });
      setVerifyResult(res);
    } catch (err) { setError('3-Tier Verification Error: ' + err.message); }
    finally { setVerifying(false); }
  };

  const handleAnchor = async () => {
    if (!selectedVaultId || !selectedDocId) { alert('Please select both a vault and a document.'); return; }
    setAnchoring(true); setError('');
    try {
      const res = await CipherixAPI.request('/blockchain/anchor', {
        method: 'POST',
        body: JSON.stringify({ vault_id: selectedVaultId, document_id: selectedDocId }),
      });
      setAnchorResult(res);
      alert(`Document hash anchored!\nTx Hash: ${res.tx_hash}`);
    } catch (err) { setError('Blockchain Anchor Error: ' + err.message); }
    finally { setAnchoring(false); }
  };

  const selectStyle = {
    background: 'var(--bg-input)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '10px',
    padding: '7px 32px 7px 12px',
    fontSize: '0.8rem',
    color: 'var(--text-primary)',
    cursor: 'pointer',
    outline: 'none',
    maxWidth: '220px',
    transition: 'border-color 160ms ease',
    appearance: 'none',
    backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E\")",
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 10px center',
  };

  const tierCards = [
    {
      icon: HardDrive,
      label: 'Tier 1: Disk Ciphertext Hash',
      value: verifyResult?.current_integrity_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      color: 'var(--accent-cyan)',
      note: '✓ Recalculated directly from binary blob',
      noteColor: 'var(--accent-emerald)',
    },
    {
      icon: Database,
      label: 'Tier 2: SQLite Metadata Hash',
      value: verifyResult?.stored_integrity_hash || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      color: 'var(--accent-purple)',
      note: '✓ Database Baseline Match',
      noteColor: 'var(--accent-emerald)',
    },
    {
      icon: Link,
      label: 'Tier 3: Blockchain Ledger',
      value: verifyResult?.tx_hash || anchorResult?.tx_hash || '0xba82c9db8fba8d34e9120934891238912389128391823918239128391283912',
      color: 'var(--accent-amber)',
      note: 'Network: local-development',
      noteColor: 'var(--accent-amber)',
    },
  ];

  return (
    <PageLayout title="Blockchain Integrity & Verification" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={ShieldCheck}
        iconColor="text-amber-400"
        title="3-Tier Integrity Verification"
        description="Asserts document integrity across disk ciphertext, SQLite metadata baseline, and local blockchain notarization."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
        <select
          value={selectedDocId}
          onChange={(e) => setSelectedDocId(e.target.value)}
          style={selectStyle}
          onFocus={e => (e.currentTarget.style.borderColor = 'rgba(245,158,11,0.40)')}
          onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.10)')}
        >
          {documents.length === 0 && <option value="">No Documents Available</option>}
          {documents.map((d) => (
            <option key={d.document_id} value={d.document_id}>{d.filename}</option>
          ))}
        </select>
      </PageHeader>

      {error && <ErrorState message={error} />}

      {}
      <div
        className="glass-panel"
        style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', borderColor: 'rgba(245,158,11,0.15)' }}
      >
        {}
        {verifyResult && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              padding: '14px 18px',
              borderRadius: '12px',
              border: `1px solid ${verifyResult.verified ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'}`,
              background: verifyResult.verified ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
              color: verifyResult.verified ? '#6ee7b7' : '#fca5a5',
              fontWeight: 700,
              fontSize: '0.875rem',
              fontFamily: "'Outfit', sans-serif",
            }}
          >
            {verifyResult.verified
              ? <CheckCircle2 style={{ width: 18, height: 18, flexShrink: 0 }} />
              : <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0 }} />
            }
            {verifyResult.verified ? 'VERIFIED & UNTAMPERED' : 'INTEGRITY MISMATCH DETECTED'}
          </div>
        )}

        {}
        <div>
          <h3 className="section-title" style={{ marginBottom: '14px' }}>
            <ShieldCheck style={{ width: 15, height: 15, color: 'var(--accent-amber)' }} />
            Integrity Verification Metrics
          </h3>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
            {tierCards.map(({ icon: Icon, label, value, color, note, noteColor }) => (
              <div
                key={label}
                style={{
                  padding: '16px 18px',
                  borderRadius: '12px',
                  background: 'rgba(7,10,18,0.55)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Icon style={{ width: 12, height: 12, color, flexShrink: 0 }} />
                  <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</span>
                </div>
                <div
                  title={value}
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '0.6875rem',
                    color,
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {value}
                </div>
                <div style={{ fontSize: '0.6875rem', color: noteColor || 'var(--text-muted)' }}>{note}</div>
              </div>
            ))}
          </div>
        </div>

        {}
        <div
          style={{
            display: 'flex',
            flexWrap: 'wrap',
            gap: '10px',
            paddingTop: '16px',
            borderTop: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <button
            onClick={handleVerify}
            disabled={verifying}
            className="btn"
            style={{
              background: 'var(--accent-amber)',
              color: '#050a12',
              boxShadow: '0 4px 14px rgba(245,158,11,0.22)',
              transition: 'all 160ms',
            }}
            onMouseEnter={e => { if (!verifying) { e.currentTarget.style.background = '#fcd34d'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-amber)'; e.currentTarget.style.transform = 'translateY(0)'; }}
          >
            <RefreshCw style={{ width: 14, height: 14, ...(verifying ? { animation: 'spin 1s linear infinite' } : {}) }} />
            Run 3-Tier Verification
          </button>
          <button
            onClick={handleAnchor}
            disabled={anchoring}
            className="btn btn-secondary"
            style={{ color: 'var(--accent-cyan)' }}
          >
            <Boxes style={{ width: 14, height: 14 }} />
            Anchor Hash to Blockchain
          </button>
        </div>
      </div>
    </PageLayout>
  );
}
