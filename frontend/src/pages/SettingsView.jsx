import React from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { Settings, Server, Clock, Link, Cpu, ShieldAlert } from 'lucide-react';

function ConfigCard({ label, value, valueColor, description, icon: Icon, iconColor }) {
  return (
    <div
      style={{
        padding: '18px 20px',
        borderRadius: '12px',
        background: 'rgba(7,10,18,0.50)',
        border: '1px solid rgba(255,255,255,0.07)',
        display: 'flex',
        flexDirection: 'column',
        gap: '6px',
        transition: 'border-color 160ms ease',
      }}
      onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.13)')}
      onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.07)')}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
        {Icon && <Icon style={{ width: 13, height: 13, color: iconColor || 'var(--text-muted)', flexShrink: 0 }} />}
        <span
          style={{
            fontSize: '0.6875rem',
            fontWeight: 700,
            letterSpacing: '0.06em',
            textTransform: 'uppercase',
            color: 'var(--text-muted)',
          }}
        >
          {label}
        </span>
      </div>
      <div
        style={{
          fontFamily: "'JetBrains Mono', 'Courier New', monospace",
          fontSize: '0.9rem',
          fontWeight: 700,
          color: valueColor || 'var(--accent-cyan)',
        }}
      >
        {value}
      </div>
      {description && (
        <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '2px' }}>
          {description}
        </div>
      )}
    </div>
  );
}

export function SettingsView({ user, onLogout }) {
  return (
    <PageLayout title="Settings & Preferences" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={Settings}
        iconColor="text-slate-400"
        title="System Configuration & Preferences"
        description="Runtime configuration, security policy parameters, and system-level settings."
      />

      {/* Runtime Config */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
        <h3 className="section-title">
          <Server style={{ width: 16, height: 16, color: 'var(--accent-cyan)' }} />
          Runtime Configuration
        </h3>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
          <ConfigCard
            label="App Environment"
            value="DEVELOPMENT"
            valueColor="var(--accent-cyan)"
            description="Production guard active"
            icon={Server}
            iconColor="var(--accent-cyan)"
          />
          <ConfigCard
            label="JWT Expiration"
            value="30 Minutes"
            valueColor="var(--accent-purple)"
            description="Refresh token rotation enabled"
            icon={Clock}
            iconColor="var(--accent-purple)"
          />
          <ConfigCard
            label="Blockchain Network"
            value="local-development"
            valueColor="var(--accent-amber)"
            description="Deterministic HMAC notarization"
            icon={Link}
            iconColor="var(--accent-amber)"
          />
          <ConfigCard
            label="Local LLM Backend"
            value="llama3.2:1b"
            valueColor="var(--accent-emerald)"
            description="Zero-knowledge local inference"
            icon={Cpu}
            iconColor="var(--accent-emerald)"
          />
        </div>
      </div>

      {/* Rate Limiting */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <h3 className="section-title">
          <ShieldAlert style={{ width: 16, height: 16, color: 'var(--accent-danger)' }} />
          Rate Throttling Protections
        </h3>

        <p style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.6 }}>
          Sliding window rate limiters protect against brute-force and DoS attacks.
        </p>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {[
            {
              endpoint: '/login, /register',
              limit: '10 req / min',
              label: 'Auth Endpoints',
              color: 'var(--accent-danger)',
            },
            {
              endpoint: '/search, /rag, /blockchain, /computer-access',
              limit: '30 req / min',
              label: 'Expensive Endpoints',
              color: 'var(--accent-amber)',
            },
          ].map((rule) => (
            <div
              key={rule.label}
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                justifyContent: 'space-between',
                gap: '16px',
                padding: '14px 18px',
                borderRadius: '10px',
                background: 'rgba(7,10,18,0.50)',
                border: '1px solid rgba(255,255,255,0.06)',
              }}
            >
              <div>
                <div style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '4px' }}>
                  {rule.label}
                </div>
                <div
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: '0.6875rem',
                    color: 'var(--text-muted)',
                  }}
                >
                  {rule.endpoint}
                </div>
              </div>
              <span
                style={{
                  padding: '4px 12px',
                  borderRadius: '9999px',
                  background: `${rule.color}18`,
                  border: `1px solid ${rule.color}40`,
                  color: rule.color,
                  fontSize: '0.8125rem',
                  fontWeight: 700,
                  fontFamily: "'JetBrains Mono', monospace",
                  whiteSpace: 'nowrap',
                  flexShrink: 0,
                }}
              >
                {rule.limit}
              </span>
            </div>
          ))}
        </div>
      </div>
    </PageLayout>
  );
}
