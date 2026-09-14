import React from 'react';
import { Loader2, AlertTriangle, Info, CheckCircle2, X, ShieldOff } from 'lucide-react';


export function LoadingState({ message = 'Loading secure data...' }) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '14px',
        padding: '52px 24px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        textAlign: 'center',
      }}
    >
      <div
        style={{
          width: 44,
          height: 44,
          borderRadius: '50%',
          background: 'rgba(34,211,238,0.08)',
          border: '1px solid rgba(34,211,238,0.20)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
      </div>
      <p
        style={{
          fontSize: '0.8125rem',
          color: 'var(--text-secondary)',
          margin: 0,
          fontWeight: 500,
        }}
      >
        {message}
      </p>
    </div>
  );
}


export function EmptyState({
  title = 'No items found',
  description = 'Click the action button above to create or upload items.',
  actionLabel,
  onAction,
}) {
  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        gap: '14px',
        padding: '60px 24px',
        background: 'var(--bg-card)',
        border: '1px solid var(--border-subtle)',
        borderRadius: 'var(--radius-lg)',
        textAlign: 'center',
      }}
    >
      <div
        style={{
          width: 52,
          height: 52,
          borderRadius: '16px',
          background: 'rgba(100,116,139,0.10)',
          border: '1px solid rgba(100,116,139,0.20)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        <Info style={{ width: 24, height: 24, color: '#64748B' }} />
      </div>

      <div>
        <h3
          style={{
            fontSize: '0.9375rem',
            fontWeight: 700,
            fontFamily: "'Outfit', sans-serif",
            color: 'var(--text-primary)',
            margin: '0 0 6px 0',
          }}
        >
          {title}
        </h3>
        <p
          style={{
            fontSize: '0.8rem',
            color: 'var(--text-secondary)',
            maxWidth: '340px',
            margin: 0,
            lineHeight: 1.6,
          }}
        >
          {description}
        </p>
      </div>

      {actionLabel && (
        <button
          onClick={onAction}
          className="btn btn-primary"
          style={{ marginTop: '4px' }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}


export function ErrorState({ message, onRetry }) {
  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        gap: '12px',
        padding: '14px 18px',
        background: 'rgba(239,68,68,0.06)',
        border: '1px solid rgba(239,68,68,0.25)',
        borderRadius: 'var(--radius-md)',
        fontSize: '0.8125rem',
        color: '#fca5a5',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <AlertTriangle style={{ width: 16, height: 16, color: '#EF4444', flexShrink: 0 }} />
        <span>{message || 'An unexpected error occurred.'}</span>
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          style={{
            padding: '5px 12px',
            borderRadius: '8px',
            background: 'rgba(239,68,68,0.15)',
            border: '1px solid rgba(239,68,68,0.35)',
            color: '#fca5a5',
            fontSize: '0.75rem',
            fontWeight: 700,
            cursor: 'pointer',
            flexShrink: 0,
            transition: 'background 160ms',
          }}
          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(239,68,68,0.25)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'rgba(239,68,68,0.15)')}
        >
          Retry
        </button>
      )}
    </div>
  );
}


export function ConfirmDialog({
  isOpen,
  title,
  message,
  confirmLabel = 'Delete',
  onConfirm,
  onCancel,
  isDanger = true,
}) {
  if (!isOpen) return null;
  return (
    <div className="modal-backdrop">
      <div className="modal-panel" style={{ maxWidth: '420px' }}>
        <div className="modal-header">
          <h3 className="modal-title">{title}</h3>
          <button
            onClick={onCancel}
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
            onMouseEnter={e => {
              e.currentTarget.style.background = 'rgba(255,255,255,0.06)';
              e.currentTarget.style.color = 'var(--text-primary)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.background = 'transparent';
              e.currentTarget.style.color = 'var(--text-muted)';
            }}
          >
            <X style={{ width: 16, height: 16 }} />
          </button>
        </div>

        <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', lineHeight: 1.65, margin: 0 }}>
          {message}
        </p>

        <div className="modal-footer">
          <button onClick={onCancel} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`btn ${isDanger ? 'btn-danger' : 'btn-primary'}`}
            style={{ fontSize: '0.8rem' }}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}


export function VaultSelector({ vaults = [], selectedVaultId, onChange, label = 'Vault' }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
      {label && (
        <label
          style={{
            fontSize: '0.6875rem',
            fontWeight: 700,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
            whiteSpace: 'nowrap',
            flexShrink: 0,
          }}
          className="hidden sm:block"
        >
          {label}:
        </label>
      )}
      <select
        value={selectedVaultId}
        onChange={(e) => onChange(e.target.value)}
        style={{
          background: 'var(--bg-input)',
          border: '1px solid rgba(255,255,255,0.10)',
          borderRadius: '10px',
          padding: '7px 32px 7px 12px',
          fontSize: '0.8rem',
          color: 'var(--text-primary)',
          cursor: 'pointer',
          outline: 'none',
          maxWidth: '200px',
          minWidth: '130px',
          appearance: 'none',
          backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E\")",
          backgroundRepeat: 'no-repeat',
          backgroundPosition: 'right 10px center',
          transition: 'border-color 160ms ease',
        }}
        onFocus={e => (e.currentTarget.style.borderColor = 'rgba(34,211,238,0.45)')}
        onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.10)')}
      >
        {vaults.length === 0 && <option value="">No Vaults Available</option>}
        {vaults.map((v) => (
          <option key={v.vault_id} value={v.vault_id}>
            {v.name} ({v.status})
          </option>
        ))}
      </select>
    </div>
  );
}


export function Toast({ message, type = 'success', onClose }) {
  if (!message) return null;
  return (
    <div
      style={{
        position: 'fixed',
        bottom: '24px',
        right: '24px',
        zIndex: 80,
        padding: '12px 16px',
        borderRadius: '12px',
        border: `1px solid ${type === 'success' ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'}`,
        background: type === 'success' ? 'rgba(16,185,129,0.10)' : 'rgba(239,68,68,0.10)',
        color: type === 'success' ? '#6ee7b7' : '#fca5a5',
        fontSize: '0.8125rem',
        fontWeight: 600,
        display: 'flex',
        alignItems: 'center',
        gap: '10px',
        boxShadow: '0 16px 40px rgba(0,0,0,0.55)',
        backdropFilter: 'blur(12px)',
        animation: 'modal-slide 220ms ease',
      }}
    >
      {type === 'success'
        ? <CheckCircle2 style={{ width: 16, height: 16, color: '#10B981', flexShrink: 0 }} />
        : <AlertTriangle style={{ width: 16, height: 16, color: '#EF4444', flexShrink: 0 }} />
      }
      <span>{message}</span>
      <button
        onClick={onClose}
        style={{
          background: 'transparent',
          border: 'none',
          color: 'inherit',
          opacity: 0.6,
          cursor: 'pointer',
          marginLeft: '4px',
          display: 'flex',
          alignItems: 'center',
        }}
      >
        <X style={{ width: 14, height: 14 }} />
      </button>
    </div>
  );
}
