import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, ArrowRight, CheckCircle2, AlertTriangle, Eye, EyeOff } from 'lucide-react';
import { CipherixAPI } from '../api';
import { PageTransition } from '../components/PageTransition';

export function AuthView({ onLoginSuccess }) {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [successMsg, setSuccessMsg] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccessMsg('');

    if (!username.trim() || !password.trim()) {
      setError('Username and password are required.');
      return;
    }
    if (isRegister && password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setLoading(true);
    try {
      if (isRegister) {
        await CipherixAPI.request('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username: username.trim(), password }),
        });
        setSuccessMsg('Registration successful! You can now log in.');
        setIsRegister(false);
        setPassword(''); setConfirmPassword('');
      } else {
        const res = await CipherixAPI.request('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: username.trim(), password }),
        });
        if (res.access_token) {
          CipherixAPI.setAuthToken(res.access_token);
          localStorage.setItem('cipherix_username', username.trim());
          if (onLoginSuccess) onLoginSuccess({ username: username.trim(), role: 'Administrator' });
          navigate('/');
        } else {
          setError('Invalid login response from server.');
        }
      }
    } catch (err) {
      setError(err.message || 'Authentication failed. Check credentials.');
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
        {/* Background orbs */}
        <div
          style={{
            position: 'absolute',
            top: '20%',
            left: '50%',
            transform: 'translateX(-50%)',
            width: '600px',
            height: '600px',
            background: 'radial-gradient(circle, rgba(34,211,238,0.06) 0%, transparent 65%)',
            pointerEvents: 'none',
          }}
        />
        <div
          style={{
            position: 'absolute',
            bottom: '15%',
            left: '20%',
            width: '480px',
            height: '480px',
            background: 'radial-gradient(circle, rgba(168,85,247,0.05) 0%, transparent 65%)',
            pointerEvents: 'none',
          }}
        />

        {/* Login Card */}
        <div
          style={{
            maxWidth: '420px',
            width: '100%',
            background: 'rgba(16,24,39,0.90)',
            border: '1px solid rgba(255,255,255,0.09)',
            borderRadius: '20px',
            padding: '40px 36px',
            boxShadow: '0 24px 64px rgba(0,0,0,0.70), 0 0 0 1px rgba(34,211,238,0.06)',
            backdropFilter: 'blur(20px)',
            position: 'relative',
            zIndex: 10,
          }}
        >
          {/* Header */}
          <div style={{ textAlign: 'center', marginBottom: '32px' }}>
            <div
              style={{
                width: 56,
                height: 56,
                borderRadius: '16px',
                background: 'rgba(34,211,238,0.10)',
                border: '1px solid rgba(34,211,238,0.25)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                margin: '0 auto 16px auto',
              }}
            >
              <Shield style={{ width: 28, height: 28, color: '#22D3EE' }} />
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
              {isRegister ? 'Create Account' : 'Authenticate Session'}
            </h1>
            <p style={{ fontSize: '0.8125rem', color: '#64748B', margin: 0, lineHeight: 1.55 }}>
              {isRegister
                ? 'Register credentials for zero-knowledge vault access'
                : 'Enter credentials to access your encrypted command center'
              }
            </p>
          </div>

          {/* Alerts */}
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

          {/* Form */}
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
                Username
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
                  placeholder="e.g. rachit_admin"
                  style={inputStyle}
                  onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                />
              </div>
            </div>

            {/* Password */}
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
                Password
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
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password..."
                  style={{ ...inputStyle, paddingRight: '42px' }}
                  onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
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
                    transition: 'color 160ms',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.color = '#94A3B8')}
                  onMouseLeave={e => (e.currentTarget.style.color = '#475569')}
                >
                  {showPassword ? <EyeOff style={{ width: 15, height: 15 }} /> : <Eye style={{ width: 15, height: 15 }} />}
                </button>
              </div>
            </div>

            {/* Confirm Password (register only) */}
            {isRegister && (
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
                  Confirm Password
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
                    placeholder="Confirm password..."
                    style={inputStyle}
                    onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                    onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                  />
                </div>
              </div>
            )}

            {/* Submit */}
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
                background: 'linear-gradient(135deg, #22D3EE, #8B5CF6)',
                color: '#050a12',
                fontWeight: 800,
                fontSize: '0.9rem',
                fontFamily: "'Outfit', sans-serif",
                border: 'none',
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.7 : 1,
                boxShadow: '0 6px 20px rgba(34,211,238,0.25)',
                transition: 'all 160ms',
                letterSpacing: '0.01em',
                marginTop: '4px',
              }}
              onMouseEnter={e => { if (!loading) { e.currentTarget.style.opacity = '0.92'; e.currentTarget.style.transform = 'translateY(-1px)'; e.currentTarget.style.boxShadow = '0 8px 24px rgba(34,211,238,0.35)'; } }}
              onMouseLeave={e => { e.currentTarget.style.opacity = '1'; e.currentTarget.style.transform = 'translateY(0)'; e.currentTarget.style.boxShadow = '0 6px 20px rgba(34,211,238,0.25)'; }}
            >
              <span>{loading ? 'Authenticating...' : isRegister ? 'Register Account' : 'Authenticate Session'}</span>
              <ArrowRight style={{ width: 16, height: 16 }} />
            </button>
          </form>

          {/* Toggle */}
          <div
            style={{
              marginTop: '24px',
              paddingTop: '20px',
              borderTop: '1px solid rgba(255,255,255,0.07)',
              textAlign: 'center',
              fontSize: '0.8125rem',
              color: '#64748B',
            }}
          >
            {isRegister ? (
              <>
                Already have an account?{' '}
                <button
                  onClick={() => { setIsRegister(false); setError(''); }}
                  style={{ background: 'none', border: 'none', color: '#22D3EE', fontWeight: 700, cursor: 'pointer', fontSize: 'inherit', transition: 'opacity 160ms' }}
                  onMouseEnter={e => (e.currentTarget.style.opacity = '0.75')}
                  onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
                >
                  Log in
                </button>
              </>
            ) : (
              <>
                Need a new account?{' '}
                <button
                  onClick={() => { setIsRegister(true); setError(''); }}
                  style={{ background: 'none', border: 'none', color: '#22D3EE', fontWeight: 700, cursor: 'pointer', fontSize: 'inherit', transition: 'opacity 160ms' }}
                  onMouseEnter={e => (e.currentTarget.style.opacity = '0.75')}
                  onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
                >
                  Register
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </PageTransition>
  );
}
