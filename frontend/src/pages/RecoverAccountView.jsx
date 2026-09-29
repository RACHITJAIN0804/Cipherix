import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Shield, KeyRound, User, Lock, ArrowRight, CheckCircle2, AlertTriangle, Eye, EyeOff, ArrowLeft } from 'lucide-react';
import { CipherixAPI } from '../api';
import { PageTransition } from '../components/PageTransition';

export function RecoverAccountView({ onLoginSuccess }) {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [seed, setSeed] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccessMsg('');

    const trimmedUsername = username.trim();
    const trimmedSeed = seed.trim();
    const words = trimmedSeed ? trimmedSeed.split(/\s+/) : [];

    if (!trimmedUsername) {
      setError('Username is required.');
      return;
    }
    if (!trimmedSeed) {
      setError('16-word recovery seed is required.');
      return;
    }
    if (words.length !== 16) {
      setError(`Recovery seed must contain exactly 16 words (found ${words.length}).`);
      return;
    }
    if (!newPassword) {
      setError('New password is required.');
      return;
    }
    if (newPassword.length < 8) {
      setError('New password must be at least 8 characters long.');
      return;
    }
    if (newPassword !== confirmPassword) {
      setError('New password and confirmation password do not match.');
      return;
    }

    setLoading(true);
    try {
      const res = await CipherixAPI.request('/auth/recover', {
        method: 'POST',
        body: JSON.stringify({
          username: trimmedUsername,
          seed: trimmedSeed,
          new_password: newPassword,
        }),
      });

      // Clear sensitive form state immediately after request completes
      setSeed('');
      setNewPassword('');
      setConfirmPassword('');

      if (res && res.access_token) {
        CipherixAPI.setAuthToken(res.access_token);
        localStorage.setItem('cipherix_username', trimmedUsername);
        setSuccessMsg('Account recovered successfully! Redirecting to dashboard...');

        setTimeout(() => {
          if (onLoginSuccess) {
            onLoginSuccess({ username: trimmedUsername, role: 'Administrator' });
          }
          navigate('/');
        }, 1500);
      } else {
        setSuccessMsg('Account access recovered! You can now log in with your new password.');
      }
    } catch (err) {
      setError(err.message || 'Account recovery failed. Please verify your username and recovery seed.');
    } finally {
      setLoading(false);
    }
  };

  const inputStyle = {
    width: '100%',
    background: 'rgba(13,21,34,0.80)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '12px',
    padding: '12px 14px 12px 42px',
    fontSize: '0.875rem',
    color: '#E2E8F0',
    outline: 'none',
    transition: 'border-color 160ms ease, box-shadow 160ms ease',
    boxSizing: 'border-box',
    fontFamily: 'inherit',
  };

  return (
    <PageTransition>
      <div
        style={{
          minHeight: '100vh',
          background: '#080B12',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '24px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            top: '20%',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '600px',
            height: '600px',
            background: 'radial-gradient(circle, rgba(168,85,247,0.06) 0%, transparent 65%)',
            pointerEvents: 'none',
          }}
        />

        <div
          style={{
            maxWidth: '460px',
            width: '100%',
            background: 'rgba(16,24,39,0.90)',
            border: '1px solid rgba(255,255,255,0.09)',
            borderRadius: '20px',
            padding: '36px 32px',
            boxShadow: '0 24px 64px rgba(0,0,0,0.70), 0 0 0 1px rgba(168,85,247,0.06)',
            backdropFilter: 'blur(20px)',
            position: 'relative',
            zIndex: 10,
          }}
        >
          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: '28px' }}>
            <div
              style={{
                width: 52,
                height: 52,
                borderRadius: '16px',
                background: 'rgba(168,85,247,0.10)',
                border: '1px solid rgba(168,85,247,0.25)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 14px auto',
              }}
            >
              <KeyRound style={{ width: 26, height: 26, color: '#c084fc' }} />
            </div>
            <h1
              style={{
                fontFamily: "'Outfit', sans-serif",
                fontSize: '1.4rem',
                fontWeight: 800,
                color: '#E2E8F0',
                margin: '0 0 6px 0',
                letterSpacing: '-0.01em',
              }}
            >
              Emergency Account Recovery
            </h1>
            <p style={{ fontSize: '0.8125rem', color: '#64748B', margin: 0, lineHeight: 1.55 }}>
              Enter your account username and 16-word BIP-39 seed phrase to reset your password and recover vault access.
            </p>
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
                marginBottom: '20px',
              }}
            >
              <AlertTriangle style={{ width: 15, height: 15, flexShrink: 0 }} />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '10px',
                padding: '12px 14px',
                borderRadius: '10px',
                background: 'rgba(16,185,129,0.08)',
                border: '1px solid rgba(16,185,129,0.28)',
                color: '#6ee7b7',
                fontSize: '0.8125rem',
                marginBottom: '20px',
              }}
            >
              <CheckCircle2 style={{ width: 15, height: 15, flexShrink: 0 }} />
              <span>{successMsg}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {/* Username */}
            <div>
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
                Account Username
              </label>
              <div style={{ position: 'relative' }}>
                <User
                  style={{
                    position: 'absolute',
                    left: '14px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    width: 15,
                    height: 15,
                    color: '#475569',
                  }}
                />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username..."
                  style={inputStyle}
                  onFocus={(e) => {
                    e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                    e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.08)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
              </div>
            </div>

            {/* 16-Word Recovery Seed */}
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <label
                  style={{
                    fontSize: '0.6875rem',
                    fontWeight: 700,
                    letterSpacing: '0.06em',
                    textTransform: 'uppercase',
                    color: '#64748B',
                  }}
                >
                  16-Word BIP-39 Seed Phrase
                </label>
                <span style={{ fontSize: '0.7rem', color: 'var(--accent-purple)', fontWeight: 600 }}>
                  Exactly 16 Words Required
                </span>
              </div>
              <textarea
                value={seed}
                onChange={(e) => setSeed(e.target.value)}
                placeholder="e.g. alpha bravo cipher delta echo foxtrot golf hotel india juliet kilo lima mike november oscar papa"
                rows={3}
                style={{
                  width: '100%',
                  background: 'rgba(13,21,34,0.80)',
                  border: '1px solid rgba(255,255,255,0.10)',
                  borderRadius: '12px',
                  padding: '10px 14px',
                  fontSize: '0.8125rem',
                  color: 'var(--accent-cyan)',
                  fontFamily: "'JetBrains Mono', monospace",
                  outline: 'none',
                  transition: 'border-color 160ms ease, box-shadow 160ms ease',
                  boxSizing: 'border-box',
                  resize: 'vertical',
                  minHeight: '76px',
                }}
                onFocus={(e) => {
                  e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                  e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.08)';
                }}
                onBlur={(e) => {
                  e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                  e.target.style.boxShadow = 'none';
                }}
              />
            </div>

            {/* New Password */}
            <div>
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
                New Vault Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock
                  style={{
                    position: 'absolute',
                    left: '14px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    width: 15,
                    height: 15,
                    color: '#475569',
                  }}
                />
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  placeholder="Enter new password (min 8 chars)..."
                  style={{ ...inputStyle, paddingRight: '42px' }}
                  onFocus={(e) => {
                    e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                    e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.08)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: 'absolute',
                    right: '12px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'transparent',
                    border: 'none',
                    color: '#475569',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    padding: '2px',
                  }}
                >
                  {showPassword ? <EyeOff style={{ width: 15, height: 15 }} /> : <Eye style={{ width: 15, height: 15 }} />}
                </button>
              </div>
            </div>

            {/* Confirm New Password */}
            <div>
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
                Confirm New Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock
                  style={{
                    position: 'absolute',
                    left: '14px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                    width: 15,
                    height: 15,
                    color: '#475569',
                  }}
                />
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Re-enter new password..."
                  style={inputStyle}
                  onFocus={(e) => {
                    e.target.style.borderColor = 'rgba(168,85,247,0.45)';
                    e.target.style.boxShadow = '0 0 0 3px rgba(168,85,247,0.08)';
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                    e.target.style.boxShadow = 'none';
                  }}
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '8px',
                width: '100%',
                padding: '13px',
                borderRadius: '13px',
                background: 'linear-gradient(135deg, #a855f7, #6366f1)',
                color: '#ffffff',
                fontWeight: 800,
                fontSize: '0.9rem',
                fontFamily: "'Outfit', sans-serif",
                border: 'none',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.7 : 1,
                boxShadow: '0 6px 20px rgba(168,85,247,0.25)',
                transition: 'all 160ms',
                marginTop: '4px',
              }}
            >
              <span>{loading ? 'Recovering Account...' : 'Recover Account & Reset Access'}</span>
              <ArrowRight style={{ width: 16, height: 16 }} />
            </button>
          </form>

          <div
            style={{
              marginTop: '24px',
              paddingTop: '18px',
              borderTop: '1px solid rgba(255,255,255,0.07)',
              textAlign: 'center',
            }}
          >
            <Link
              to="/login"
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                color: '#94A3B8',
                fontSize: '0.8125rem',
                textDecoration: 'none',
                fontWeight: 600,
                transition: 'color 160ms',
              }}
              onMouseEnter={(e) => (e.currentTarget.style.color = '#E2E8F0')}
              onMouseLeave={(e) => (e.currentTarget.style.color = '#94A3B8')}
            >
              <ArrowLeft style={{ width: 14, height: 14 }} />
              Back to Login
            </Link>
          </div>
        </div>
      </div>
    </PageTransition>
  );
}
