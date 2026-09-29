import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import {
  LifeBuoy,
  Sparkles,
  Check,
  KeyRound,
  Copy,
  ShieldCheck,
  Lock,
  AlertTriangle,
  ArrowRight,
  RefreshCw,
  RotateCcw,
} from 'lucide-react';

export function RecoveryView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  
  // Setup wizard step: 1 = Password Input, 2 = Display 4x4 Grid, 3 = Confirm Words, 4 = Complete
  const [step, setStep] = useState(1);
  
  // Form & Seed states
  const [vaultPassword, setVaultPassword] = useState('');
  const [seedWords, setSeedWords] = useState([]); // In-memory ONLY, cleared on complete/unmount
  const [confirmPositions, setConfirmPositions] = useState([]); // Indices (e.g. [2, 7, 13])
  const [confirmInputs, setConfirmInputs] = useState({}); // { 2: "word1", 7: "word2", 13: "word3" }
  
  const [copied, setCopied] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Memory cleanup on unmount
  useEffect(() => {
    return () => {
      setSeedWords([]);
      setVaultPassword('');
    };
  }, []);

  useEffect(() => {
    async function loadVaults() {
      try {
        const data = await CipherixAPI.request('/vaults');
        const vList = Array.isArray(data) ? data : [];
        setVaults(vList);
        if (vList.length > 0 && !selectedVaultId) setSelectedVaultId(vList[0].vault_id);
      } catch (err) {
        console.warn('Failed to load vaults:', err);
      }
    }
    loadVaults();
  }, []);

  // Reset wizard flow state
  const resetFlow = () => {
    setStep(1);
    setVaultPassword('');
    setSeedWords([]);
    setConfirmPositions([]);
    setConfirmInputs({});
    setError('');
    setCopied(false);
  };

  // Step 1 -> Step 2: Call API with password
  const handleGenerateSeed = async (e) => {
    e.preventDefault();
    if (!selectedVaultId) {
      setError('Please select a vault.');
      return;
    }
    if (!vaultPassword) {
      setError('Vault password is required to generate a recovery seed.');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const res = await CipherixAPI.request(
        `/vaults/${selectedVaultId}/recovery-seed`,
        {
          method: 'POST',
          body: JSON.stringify({ password: vaultPassword }),
        }
      );

      const rawSeed = res.seed || '';
      const words = rawSeed.trim().split(/\s+/);

      if (words.length !== 16) {
        throw new Error(`Expected 16 words, but received ${words.length}.`);
      }

      setSeedWords(words);
      setVaultPassword(''); // Clear password from memory after request
      setStep(2);
    } catch (err) {
      setError(err.message || 'Seed Generation Failed.');
    } finally {
      setLoading(false);
    }
  };

  // Step 2 -> Step 3: Select 3 random word positions for confirmation
  const handleStartConfirmation = () => {
    // Pick 3 unique random indices from 0..15
    const indices = [];
    while (indices.length < 3) {
      const rand = Math.floor(Math.random() * 16);
      if (!indices.includes(rand)) {
        indices.push(rand);
      }
    }
    indices.sort((a, b) => a - b);
    setConfirmPositions(indices);
    setConfirmInputs({});
    setError('');
    setStep(3);
  };

  // Step 3 -> Step 4: Verify entered confirmation words against in-memory seedWords
  const handleVerifyConfirmation = (e) => {
    e.preventDefault();
    setError('');

    for (const pos of confirmPositions) {
      const expected = seedWords[pos]?.toLowerCase().trim();
      const entered = (confirmInputs[pos] || '').toLowerCase().trim();

      if (!entered) {
        setError(`Please enter Word #${pos + 1}.`);
        return;
      }

      if (entered !== expected) {
        setError(
          `Word #${pos + 1} does not match your generated seed phrase. Please check your backup and try again.`
        );
        return;
      }
    }

    // Confirmation successful! Clear plaintext seed from memory
    setSeedWords([]);
    setConfirmInputs({});
    setStep(4);
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
    <PageLayout title="16-Word Recovery Seed Setup" user={user} onLogout={onLogout}>
      <PageHeader
        icon={LifeBuoy}
        iconColor="text-purple-400"
        title="BIP-39 Recovery Seed Setup"
        description="16-word recovery seeds allow emergency access if passwords are lost. Follow the 3-step setup to activate recovery protection."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={(id) => { setSelectedVaultId(id); resetFlow(); }} />
      </PageHeader>

      {/* Progress Steps Indicator */}
      <div
        className="glass-panel"
        style={{
          padding: '16px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '12px',
          borderColor: 'rgba(168,85,247,0.15)',
        }}
      >
        {[
          { num: 1, label: 'Authenticate' },
          { num: 2, label: 'Backup 16 Words' },
          { num: 3, label: 'Confirm Words' },
          { num: 4, label: 'Complete' },
        ].map(({ num, label }) => {
          const isActive = step === num;
          const isDone = step > num;
          return (
            <div
              key={num}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                opacity: isActive || isDone ? 1 : 0.4,
              }}
            >
              <div
                style={{
                  width: '28px',
                  height: '28px',
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  background: isDone
                    ? 'var(--accent-emerald)'
                    : isActive
                    ? 'var(--accent-purple)'
                    : 'rgba(255,255,255,0.1)',
                  color: isDone || isActive ? '#050a12' : 'var(--text-secondary)',
                }}
              >
                {isDone ? <Check style={{ width: 14, height: 14 }} /> : num}
              </div>
              <span
                style={{
                  fontSize: '0.8125rem',
                  fontWeight: isActive ? 700 : 500,
                  color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
                }}
              >
                {label}
              </span>
            </div>
          );
        })}
      </div>

      {error && <ErrorState message={error} />}

      {/* STEP 1: Generate & Authenticate */}
      {step === 1 && (
        <div
          className="glass-panel"
          style={{
            padding: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
            borderColor: 'rgba(168,85,247,0.15)',
          }}
        >
          <div>
            <h3 className="section-title" style={{ marginBottom: '6px' }}>
              <Sparkles style={{ width: 16, height: 16, color: 'var(--accent-purple)' }} />
              Step 1 — Authenticate Vault & Generate 16-Word Seed
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
              Enter your current vault password to decrypt your Vault Key and generate your 16-word BIP-39 recovery seed.
            </p>
          </div>

          <form onSubmit={handleGenerateSeed} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div>
              <label className="form-label">Vault Password</label>
              <input
                type="password"
                value={vaultPassword}
                onChange={(e) => setVaultPassword(e.target.value)}
                placeholder="Enter current vault password..."
                style={inputStyle}
                onFocus={(e) => {
                  e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                  e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.07)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button
                type="submit"
                disabled={loading || !vaultPassword}
                className="btn"
                style={{
                  background: 'var(--accent-purple)',
                  color: '#050a12',
                  boxShadow: '0 4px 14px rgba(168,85,247,0.20)',
                }}
              >
                <Sparkles style={{ width: 14, height: 14, ...(loading ? { animation: 'spin 1s linear infinite' } : {}) }} />
                Generate 16-Word Seed
              </button>
            </div>
          </form>
        </div>
      )}

      {/* STEP 2: Display 4x4 Grid & Backup */}
      {step === 2 && (
        <div
          className="glass-panel"
          style={{
            padding: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            borderColor: 'rgba(168,85,247,0.15)',
          }}
        >
          <div>
            <h3 className="section-title" style={{ marginBottom: '6px' }}>
              <Lock style={{ width: 16, height: 16, color: 'var(--accent-purple)' }} />
              Step 2 — Backup Your 16-Word Seed Phrase
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
              Below is your 16-word recovery seed phrase. Store these words offline in a secure location.
            </p>
          </div>

          <div
            style={{
              padding: '14px 16px',
              borderRadius: '10px',
              background: 'rgba(245, 158, 11, 0.08)',
              border: '1px solid rgba(245, 158, 11, 0.25)',
              display: 'flex',
              gap: '12px',
              alignItems: 'flex-start',
              color: '#fcd34d',
              fontSize: '0.8125rem',
            }}
          >
            <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0, marginTop: '2px' }} />
            <div>
              <strong>Important Security Warning:</strong> This is the ONLY time your recovery seed phrase will be displayed. Cipherix does NOT store your plaintext seed in any file, browser storage, or database. If you lose this phrase, recovery will be impossible.
            </div>
          </div>

          {/* 4x4 Word Grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '12px',
              padding: '20px',
              background: 'rgba(0, 0, 0, 0.45)',
              borderRadius: '12px',
              border: '1px solid rgba(168, 85, 247, 0.20)',
            }}
          >
            {seedWords.map((word, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  padding: '10px 12px',
                  borderRadius: '8px',
                  background: 'rgba(15, 23, 42, 0.70)',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                }}
              >
                <span
                  style={{
                    fontSize: '0.7rem',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    minWidth: '22px',
                  }}
                >
                  #{idx + 1}
                </span>
                <span
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '0.875rem',
                    fontWeight: 600,
                    color: 'var(--accent-cyan)',
                  }}
                >
                  {word}
                </span>
              </div>
            ))}
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <button
              onClick={() => {
                navigator.clipboard.writeText(seedWords.join(' '));
                setCopied(true);
                setTimeout(() => setCopied(false), 2000);
              }}
              className="btn btn-ghost"
              style={{ gap: '6px' }}
            >
              {copied ? <Check style={{ width: 14, height: 14, color: 'var(--accent-emerald)' }} /> : <Copy style={{ width: 14, height: 14 }} />}
              {copied ? 'Copied to Clipboard!' : 'Copy Phrase'}
            </button>

            <button
              onClick={handleStartConfirmation}
              className="btn"
              style={{
                background: 'var(--accent-purple)',
                color: '#050a12',
                gap: '8px',
              }}
            >
              I Have Saved My Phrase → Confirm Backup
              <ArrowRight style={{ width: 14, height: 14 }} />
            </button>
          </div>
        </div>
      )}

      {/* STEP 3: Confirm Random Words */}
      {step === 3 && (
        <div
          className="glass-panel"
          style={{
            padding: '24px',
            display: 'flex',
            flexDirection: 'column',
            gap: '20px',
            borderColor: 'rgba(168,85,247,0.15)',
          }}
        >
          <div>
            <h3 className="section-title" style={{ marginBottom: '6px' }}>
              <ShieldCheck style={{ width: 16, height: 16, color: 'var(--accent-cyan)' }} />
              Step 3 — Verify Seed Backup
            </h3>
            <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
              To ensure your seed phrase was written down correctly, please enter the requested words from your phrase.
            </p>
          </div>

          <form onSubmit={handleVerifyConfirmation} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px' }}>
              {confirmPositions.map((pos) => (
                <div key={pos}>
                  <label className="form-label">Word #{pos + 1}</label>
                  <input
                    type="text"
                    value={confirmInputs[pos] || ''}
                    onChange={(e) =>
                      setConfirmInputs({
                        ...confirmInputs,
                        [pos]: e.target.value,
                      })
                    }
                    placeholder={`Enter word #${pos + 1}...`}
                    style={{
                      ...inputStyle,
                      fontFamily: "'JetBrains Mono', monospace",
                      color: 'var(--accent-cyan)',
                    }}
                    onFocus={(e) => {
                      e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                      e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.07)';
                    }}
                    onBlur={(e) => {
                      e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                      e.target.style.boxShadow = 'none';
                    }}
                  />
                </div>
              ))}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <button
                type="button"
                onClick={() => setStep(2)}
                className="btn btn-ghost"
              >
                ← Back to Seed Display
              </button>

              <button
                type="submit"
                className="btn btn-primary"
                style={{ gap: '8px' }}
              >
                <ShieldCheck style={{ width: 14, height: 14 }} />
                Verify & Complete Setup
              </button>
            </div>
          </form>
        </div>
      )}

      {/* STEP 4: Complete */}
      {step === 4 && (
        <div
          className="glass-panel"
          style={{
            padding: '32px 24px',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            textAlign: 'center',
            gap: '16px',
            borderColor: 'rgba(16,185,129,0.25)',
            background: 'rgba(16,185,129,0.03)',
          }}
        >
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: 'rgba(16,185,129,0.15)',
              border: '1px solid rgba(16,185,129,0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--accent-emerald)',
            }}
          >
            <ShieldCheck style={{ width: 32, height: 32 }} />
          </div>

          <div>
            <h3 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--text-primary)', margin: '0 0 6px 0' }}>
              16-Word Recovery Seed Active & Verified!
            </h3>
            <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '480px', lineHeight: 1.6 }}>
              Your vault is now protected with a 16-word BIP-39 recovery key. Keep your written backup in a safe place.
            </p>
          </div>

          <button
            onClick={resetFlow}
            className="btn btn-ghost"
            style={{ marginTop: '12px', gap: '6px' }}
          >
            <RotateCcw style={{ width: 14, height: 14 }} />
            Configure Another Vault
          </button>
        </div>
      )}
    </PageLayout>
  );
}
