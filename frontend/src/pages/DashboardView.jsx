import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { CipherixAPI } from '../api';
import {
  Vault, ShieldAlert, Boxes, ShieldCheck, Activity,
  Lock, RefreshCw, LayoutDashboard, TrendingUp,
} from 'lucide-react';


function StatCard({ label, value, valueColor, icon: Icon, iconBg, iconBorder, iconColor, footnote, footnoteColor, accentGradient }) {
  return (
    <div
      className="glass-panel stat-card p-5"
      style={{ '--accent-top': accentGradient }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <div
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              letterSpacing: '0.07em',
              textTransform: 'uppercase',
              color: 'var(--text-muted)',
            }}
          >
            {label}
          </div>
          <div
            style={{
              fontSize: '2rem',
              fontWeight: 800,
              fontFamily: "'Outfit', sans-serif",
              color: valueColor || 'var(--text-primary)',
              lineHeight: 1.15,
              marginTop: '6px',
              letterSpacing: '-0.02em',
            }}
          >
            {value}
          </div>
        </div>
        <div
          style={{
            width: 42,
            height: 42,
            borderRadius: '12px',
            background: iconBg,
            border: `1px solid ${iconBorder}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <Icon style={{ width: 20, height: 20, color: iconColor }} />
        </div>
      </div>
      <div
        style={{
          marginTop: '16px',
          display: 'flex',
          alignItems: 'center',
          gap: '6px',
          fontSize: '0.78125rem',
          color: footnoteColor || 'var(--text-secondary)',
          fontWeight: 500,
        }}
      >
        <TrendingUp style={{ width: 13, height: 13, flexShrink: 0 }} />
        <span>{footnote}</span>
      </div>
    </div>
  );
}

export function DashboardView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await CipherixAPI.request('/vaults');
      setVaults(Array.isArray(data) ? data : []);
    } catch (e) {
      console.warn(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const unlockedCount = vaults.filter(v => v.status === 'unlocked').length;

  return (
    <PageLayout title="Dashboard Overview" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={LayoutDashboard}
        iconColor="text-cyan-400"
        title="Dashboard Overview"
        description="Real-time system metrics, vault status, and security posture at a glance."
      >
        <button
          onClick={loadData}
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '6px',
            padding: '7px 14px',
            borderRadius: '10px',
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.09)',
            fontSize: '0.78rem',
            fontWeight: 600,
            color: 'var(--text-secondary)',
            cursor: 'pointer',
            transition: 'all 160ms',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.color = 'var(--accent-cyan)';
            e.currentTarget.style.borderColor = 'rgba(34,211,238,0.28)';
            e.currentTarget.style.background = 'rgba(34,211,238,0.05)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.color = 'var(--text-secondary)';
            e.currentTarget.style.borderColor = 'rgba(255,255,255,0.09)';
            e.currentTarget.style.background = 'rgba(255,255,255,0.04)';
          }}
        >
          <RefreshCw style={{ width: 13, height: 13, ...(loading ? { animation: 'spin 1s linear infinite' } : {}) }} />
          <span>Refresh</span>
        </button>
      </PageHeader>

      {}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))' }}>
        <StatCard
          label="Active Vaults"
          value={vaults.length}
          icon={Vault}
          iconBg="rgba(34,211,238,0.10)"
          iconBorder="rgba(34,211,238,0.25)"
          iconColor="var(--accent-cyan)"
          footnote="Argon2id key derived"
          footnoteColor="var(--accent-emerald)"
          accentGradient="linear-gradient(90deg, #22D3EE, #3B82F6)"
        />
        <StatCard
          label="Encrypted Documents"
          value={5}
          icon={ShieldAlert}
          iconBg="rgba(168,85,247,0.10)"
          iconBorder="rgba(168,85,247,0.25)"
          iconColor="var(--accent-purple)"
          footnote="AES-256-GCM ciphertext"
          footnoteColor="var(--accent-purple)"
          accentGradient="linear-gradient(90deg, #A855F7, #6366F1)"
        />
        <StatCard
          label="Blockchain Anchors"
          value={5}
          icon={Boxes}
          iconBg="rgba(245,158,11,0.10)"
          iconBorder="rgba(245,158,11,0.25)"
          iconColor="var(--accent-amber)"
          footnote="Tamper-proof ledger"
          footnoteColor="var(--accent-amber)"
          accentGradient="linear-gradient(90deg, #F59E0B, #EF4444)"
        />
        <StatCard
          label="Security Score"
          value="100%"
          valueColor="var(--accent-emerald)"
          icon={Activity}
          iconBg="rgba(16,185,129,0.10)"
          iconBorder="rgba(16,185,129,0.25)"
          iconColor="var(--accent-emerald)"
          footnote="0 leaks · Zero-knowledge"
          footnoteColor="var(--accent-emerald)"
          accentGradient="linear-gradient(90deg, #10B981, #22D3EE)"
        />
      </div>

      {}
      <div className="glass-panel p-6">
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            paddingBottom: '16px',
            marginBottom: '16px',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <h3 className="section-title">
            <Vault style={{ width: 17, height: 17, color: 'var(--accent-cyan)' }} />
            Vault Status Overview
          </h3>
          {vaults.length > 0 && (
            <span className="badge-tag badge-cyan">
              {unlockedCount} / {vaults.length} unlocked
            </span>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {vaults.length === 0 && !loading && (
            <p
              style={{
                fontSize: '0.8125rem',
                color: 'var(--text-muted)',
                textAlign: 'center',
                padding: '24px 0',
                margin: 0,
              }}
            >
              No vaults found. Create one in the Vaults module.
            </p>
          )}
          {vaults.map((v) => (
            <div
              key={v.vault_id}
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '13px 16px',
                borderRadius: '12px',
                background: 'rgba(7,10,18,0.50)',
                border: '1px solid rgba(255,255,255,0.06)',
                transition: 'border-color 160ms ease, background 160ms ease',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.borderColor = 'rgba(34,211,238,0.18)';
                e.currentTarget.style.background = 'rgba(34,211,238,0.03)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)';
                e.currentTarget.style.background = 'rgba(7,10,18,0.50)';
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: 36,
                    height: 36,
                    borderRadius: '10px',
                    background: 'rgba(34,211,238,0.08)',
                    border: '1px solid rgba(34,211,238,0.22)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    flexShrink: 0,
                  }}
                >
                  <Vault style={{ width: 17, height: 17, color: 'var(--accent-cyan)' }} />
                </div>
                <div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {v.name}
                  </div>
                  <div
                    style={{
                      fontSize: '0.6875rem',
                      color: 'var(--text-muted)',
                      fontFamily: "'JetBrains Mono', 'Courier New', monospace",
                      marginTop: '2px',
                    }}
                  >
                    {v.vault_id}
                  </div>
                </div>
              </div>
              <span className={`badge-tag ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}`}>
                {v.status === 'unlocked'
                  ? <Lock style={{ width: 10, height: 10 }} />
                  : <Lock style={{ width: 10, height: 10 }} />
                }
                {v.status.toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      </div>
    </PageLayout>
  );
}
