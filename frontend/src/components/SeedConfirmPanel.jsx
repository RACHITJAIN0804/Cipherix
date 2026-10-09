import React, { useState, useEffect } from 'react';
import {
  Shield,
  AlertTriangle,
  Check,
  Copy,
  Lock,
  ShieldCheck,
  ArrowRight,
} from 'lucide-react';
import { PageTransition } from './PageTransition';

export function SeedConfirmPanel({ seed, username, onConfirmed }) {
  const [seedWords] = useState(() => (seed || '').trim().split(/\s+/).filter(Boolean));
  const [step, setStep] = useState(1);
  const [copied, setCopied] = useState(false);
  const [confirmPositions, setConfirmPositions] = useState([]);
  const [confirmInputs, setConfirmInputs] = useState({});
  const [error, setError] = useState('');
  const [checkedWarning, setCheckedWarning] = useState(false);

  useEffect(() => {
    return () => {
      setConfirmInputs({});
    };
  }, []);

  const handleStartConfirmation = () => {
    if (!checkedWarning) {
      setError('Please confirm you have saved your seed phrase before continuing.');
      return;
    }
    setError('');
    const indices = [];
    while (indices.length < 3) {
      const rand = Math.floor(Math.random() * seedWords.length);
      if (!indices.includes(rand)) indices.push(rand);
    }
    indices.sort((a, b) => a - b);
    setConfirmPositions(indices);
    setConfirmInputs({});
    setStep(2);
  };

  const handleVerify = (e) => {
    e.preventDefault();
    setError('');
    for (const pos of confirmPositions) {
      const expected = (seedWords[pos] || '').toLowerCase().trim();
      const entered = (confirmInputs[pos] || '').toLowerCase().trim();
      if (!entered) {
        setError(`Please enter Word #${pos + 1}.`);
        return;
      }
      if (entered !== expected) {
        setError(
          `Word #${pos + 1} is incorrect. Please check your written backup and try again.`
        );
        return;
      }
    }
    setStep(3);
    setTimeout(() => {
      onConfirmed();
    }, 1800);
  };

  const inputBase = {
    background: 'rgba(13,21,34,0.80)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '10px',
    padding: '10px 14px',
    fontSize: '0.875rem',
    color: '#22D3EE',
    fontFamily: "'JetBrains Mono', monospace",
    outline: 'none',
    transition: 'border-color 160ms, box-shadow 160ms',
    boxSizing: 'border-box',
    width: '100%',
  };

  return (
    <PageTransition>
      <div
        style={{
          minHeight: '100vh',
          background: '#080B12',
          display: 'flex',
          alignItems: 'flex-start',
          justifyContent: 'center',
          padding: '40px 24px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'fixed',
            top: '15%',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '700px',
            height: '700px',
            background: 'radial-gradient(circle, rgba(168,85,247,0.07) 0%, transparent 65%)',
            pointerEvents: 'none',
          }}
        />

        <div
          style={{
            maxWidth: '560px',
            width: '100%',
            position: 'relative',
            zIndex: 10,
          }}
        >
          <div
            style={{
              textAlign: 'center',
              marginBottom: '28px',
            }}
          >
            <div
              style={{
                width: 60,
                height: 60,
                borderRadius: '18px',
                background: 'rgba(168,85,247,0.12)',
                border: '1px solid rgba(168,85,247,0.30)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px auto',
              }}
            >
              <Shield style={{ width: 30, height: 30, color: '#c084fc' }} />
            </div>
            <h1
              style={{
                fontFamily: "'Outfit', sans-serif",
                fontSize: '1.5rem',
                fontWeight: 800,
                color: '#E2E8F0',
                margin: '0 0 6px 0',
                letterSpacing: '-0.01em',
              }}
            >
              Save Your Recovery Seed
            </h1>
            <p
              style={{
                fontSize: '0.8125rem',
                color: '#64748B',
                margin: 0,
                lineHeight: 1.6,
              }}
            >
              Account created for <strong style={{ color: '#94A3B8' }}>{username}</strong>.
              Your 16-word recovery seed is shown below.
            </p>
          </div>

          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              gap: '8px',
              marginBottom: '24px',
            }}
          >
            {[
              { n: 1, label: 'View Seed' },
              { n: 2, label: 'Confirm Backup' },
              { n: 3, label: 'Complete' },
            ].map(({ n, label }) => {
              const active = step === n;
              const done = step > n;
              return (
                <div
                  key={n}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    opacity: active || done ? 1 : 0.38,
                  }}
                >
                  <div
                    style={{
                      width: 26,
                      height: 26,
                      borderRadius: '50%',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      background: done
                        ? '#10B981'
                        : active
                        ? '#a855f7'
                        : 'rgba(255,255,255,0.08)',
                      color: done || active ? '#050a12' : '#94A3B8',
                    }}
                  >
                    {done ? <Check style={{ width: 13, height: 13 }} /> : n}
                  </div>
                  <span
                    style={{
                      fontSize: '0.75rem',
                      fontWeight: active ? 700 : 500,
                      color: active ? '#E2E8F0' : '#64748B',
                    }}
                  >
                    {label}
                  </span>
                  {n < 3 && (
                    <div
                      style={{
                        width: '24px',
                        height: '1px',
                        background: done ? '#10B981' : 'rgba(255,255,255,0.12)',
                        marginLeft: '4px',
                      }}
                    />
                  )}
                </div>
              );
            })}
          </div>

          {error && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '12px 14px',
                borderRadius: '10px',
                background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.28)',
                color: '#fca5a5',
                fontSize: '0.8125rem',
                marginBottom: '18px',
              }}
            >
              <AlertTriangle style={{ width: 15, height: 15, flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {step === 1 && (
            <div
              style={{
                background: 'rgba(16,24,39,0.90)',
                border: '1px solid rgba(168,85,247,0.18)',
                borderRadius: '20px',
                padding: '28px',
                backdropFilter: 'blur(20px)',
                display: 'flex',
                flexDirection: 'column',
                gap: '20px',
              }}
            >
              <div
                style={{
                  padding: '14px 16px',
                  borderRadius: '10px',
                  background: 'rgba(245,158,11,0.08)',
                  border: '1px solid rgba(245,158,11,0.28)',
                  display: 'flex',
                  gap: '12px',
                  alignItems: 'flex-start',
                  color: '#fcd34d',
                  fontSize: '0.8125rem',
                  lineHeight: 1.6,
                }}
              >
                <AlertTriangle
                  style={{ width: 18, height: 18, flexShrink: 0, marginTop: '1px' }}
                />
                <div>
                  <strong>This is shown only once.</strong> Cipherix never stores your
                  plaintext seed. Write down all 16 words in order and keep them
                  somewhere secure and offline.
                </div>
              </div>

              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, 1fr)',
                  gap: '10px',
                  padding: '18px',
                  background: 'rgba(0,0,0,0.40)',
                  borderRadius: '12px',
                  border: '1px solid rgba(168,85,247,0.18)',
                }}
              >
                {seedWords.map((word, idx) => (
                  <div
                    key={idx}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '7px',
                      padding: '9px 10px',
                      borderRadius: '8px',
                      background: 'rgba(15,23,42,0.70)',
                      border: '1px solid rgba(255,255,255,0.07)',
                    }}
                  >
                    <span
                      style={{
                        fontSize: '0.65rem',
                        fontWeight: 700,
                        color: '#475569',
                        minWidth: '18px',
                      }}
                    >
                      #{idx + 1}
                    </span>
                    <span
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize: '0.8125rem',
                        fontWeight: 600,
                        color: '#22D3EE',
                      }}
                    >
                      {word}
                    </span>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button
                  type="button"
                  onClick={() => {
                    navigator.clipboard.writeText(seedWords.join(' '));
                    setCopied(true);
                    setTimeout(() => setCopied(false), 2000);
                  }}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    background: 'transparent',
                    border: '1px solid rgba(255,255,255,0.12)',
                    borderRadius: '8px',
                    padding: '7px 14px',
                    color: copied ? '#10B981' : '#94A3B8',
                    fontSize: '0.8125rem',
                    cursor: 'pointer',
                    transition: 'all 160ms',
                  }}
                >
                  {copied ? (
                    <Check style={{ width: 13, height: 13 }} />
                  ) : (
                    <Copy style={{ width: 13, height: 13 }} />
                  )}
                  {copied ? 'Copied!' : 'Copy all words'}
                </button>
              </div>

              <label
                style={{
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '12px',
                  cursor: 'pointer',
                  padding: '14px',
                  borderRadius: '10px',
                  background: checkedWarning
                    ? 'rgba(168,85,247,0.07)'
                    : 'rgba(255,255,255,0.03)',
                  border: checkedWarning
                    ? '1px solid rgba(168,85,247,0.30)'
                    : '1px solid rgba(255,255,255,0.08)',
                  transition: 'all 160ms',
                }}
              >
                <input
                  type="checkbox"
                  id="seed-backup-confirm"
                  checked={checkedWarning}
                  onChange={(e) => {
                    setCheckedWarning(e.target.checked);
                    if (e.target.checked) setError('');
                  }}
                  style={{ width: 16, height: 16, marginTop: '2px', cursor: 'pointer', accentColor: '#a855f7' }}
                />
                <span style={{ fontSize: '0.8125rem', color: '#CBD5E1', lineHeight: 1.6 }}>
                  I have written down all 16 words in order and stored them in a secure
                  location. I understand that if I lose this seed phrase, I cannot recover
                  my vault.
                </span>
              </label>

              <button
                type="button"
                onClick={handleStartConfirmation}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  gap: '8px',
                  width: '100%',
                  padding: '13px',
                  borderRadius: '13px',
                  background: checkedWarning
                    ? 'linear-gradient(135deg, #a855f7, #6366f1)'
                    : 'rgba(255,255,255,0.06)',
                  color: checkedWarning ? '#ffffff' : '#475569',
                  fontWeight: 800,
                  fontSize: '0.9rem',
                  fontFamily: "'Outfit', sans-serif",
                  border: 'none',
                  cursor: checkedWarning ? 'pointer' : 'not-allowed',
                  boxShadow: checkedWarning ? '0 6px 20px rgba(168,85,247,0.25)' : 'none',
                  transition: 'all 160ms',
                }}
              >
                <span>I Have Saved My Seed — Verify Backup</span>
                <ArrowRight style={{ width: 16, height: 16 }} />
              </button>
            </div>
          )}

          {step === 2 && (
            <div
              style={{
                background: 'rgba(16,24,39,0.90)',
                border: '1px solid rgba(34,211,238,0.18)',
                borderRadius: '20px',
                padding: '28px',
                backdropFilter: 'blur(20px)',
                display: 'flex',
                flexDirection: 'column',
                gap: '20px',
              }}
            >
              <div>
                <h2
                  style={{
                    fontFamily: "'Outfit', sans-serif",
                    fontSize: '1.1rem',
                    fontWeight: 700,
                    color: '#E2E8F0',
                    margin: '0 0 6px 0',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '8px',
                  }}
                >
                  <ShieldCheck style={{ width: 18, height: 18, color: '#22D3EE' }} />
                  Verify Your Backup
                </h2>
                <p style={{ fontSize: '0.8125rem', color: '#64748B', margin: 0, lineHeight: 1.6 }}>
                  Enter the requested words from your written backup to confirm you have
                  recorded them correctly.
                </p>
              </div>

              <form onSubmit={handleVerify} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '14px' }}>
                  {confirmPositions.map((pos) => (
                    <div key={pos}>
                      <label
                        style={{
                          display: 'block',
                          fontSize: '0.6875rem',
                          fontWeight: 700,
                          letterSpacing: '0.06em',
                          textTransform: 'uppercase',
                          color: '#64748B',
                          marginBottom: '6px',
                        }}
                      >
                        Word #{pos + 1}
                      </label>
                      <input
                        type="text"
                        autoComplete="off"
                        autoCorrect="off"
                        autoCapitalize="off"
                        spellCheck="false"
                        value={confirmInputs[pos] || ''}
                        onChange={(e) =>
                          setConfirmInputs({ ...confirmInputs, [pos]: e.target.value })
                        }
                        placeholder={`Word #${pos + 1}...`}
                        style={inputBase}
                        onFocus={(e) => {
                          e.target.style.borderColor = 'rgba(34,211,238,0.45)';
                          e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.07)';
                        }}
                        onBlur={(e) => {
                          e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                          e.target.style.boxShadow = 'none';
                        }}
                      />
                    </div>
                  ))}
                </div>

                <div style={{ display: 'flex', gap: '10px', justifyContent: 'space-between' }}>
                  <button
                    type="button"
                    onClick={() => { setStep(1); setError(''); }}
                    style={{
                      background: 'transparent',
                      border: '1px solid rgba(255,255,255,0.12)',
                      borderRadius: '10px',
                      padding: '10px 18px',
                      color: '#94A3B8',
                      fontSize: '0.8125rem',
                      cursor: 'pointer',
                      fontWeight: 600,
                      transition: 'all 160ms',
                    }}
                  >
                    ← Back to Seed
                  </button>

                  <button
                    type="submit"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '7px',
                      background: 'linear-gradient(135deg, #22D3EE, #8B5CF6)',
                      border: 'none',
                      borderRadius: '10px',
                      padding: '10px 20px',
                      color: '#050a12',
                      fontSize: '0.875rem',
                      fontWeight: 800,
                      cursor: 'pointer',
                      fontFamily: "'Outfit', sans-serif",
                      boxShadow: '0 4px 14px rgba(34,211,238,0.20)',
                      transition: 'all 160ms',
                    }}
                  >
                    <ShieldCheck style={{ width: 15, height: 15 }} />
                    Verify & Complete Setup
                  </button>
                </div>
              </form>
            </div>
          )}

          {step === 3 && (
            <div
              style={{
                background: 'rgba(16,24,39,0.90)',
                border: '1px solid rgba(16,185,129,0.25)',
                borderRadius: '20px',
                padding: '40px 28px',
                backdropFilter: 'blur(20px)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                textAlign: 'center',
                gap: '16px',
              }}
            >
              <div
                style={{
                  width: 64,
                  height: 64,
                  borderRadius: '50%',
                  background: 'rgba(16,185,129,0.15)',
                  border: '1px solid rgba(16,185,129,0.35)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#10B981',
                }}
              >
                <ShieldCheck style={{ width: 36, height: 36 }} />
              </div>
              <div>
                <h2
                  style={{
                    fontFamily: "'Outfit', sans-serif",
                    fontSize: '1.25rem',
                    fontWeight: 700,
                    color: '#E2E8F0',
                    margin: '0 0 6px 0',
                  }}
                >
                  Account Setup Complete!
                </h2>
                <p style={{ fontSize: '0.875rem', color: '#64748B', margin: 0, maxWidth: '380px', lineHeight: 1.6 }}>
                  Your 16-word recovery seed has been verified and your vault is
                  protected. Redirecting to your dashboard…
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </PageTransition>
  );
}
