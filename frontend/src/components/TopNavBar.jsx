import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowLeft, ChevronRight } from 'lucide-react';
import { UserProfile } from './UserProfile';

export function TopNavBar({ title, user, onLogout }) {
  const navigate = useNavigate();

  return (
    <header
      style={{
        position: 'sticky',
        top: 0,
        zIndex: 40,
        background: 'rgba(8, 11, 18, 0.92)',
        backdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
        WebkitBackdropFilter: 'blur(20px)',
      }}
    >
      <div
        style={{
          maxWidth: '1360px',
          margin: '0 auto',
          padding: '0 28px',
          height: '58px',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '16px',
        }}
      >
        {/* Left: Back breadcrumb + page title */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', minWidth: 0 }}>
          <button
            onClick={() => navigate('/')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 12px',
              borderRadius: '10px',
              background: 'rgba(255,255,255,0.04)',
              border: '1px solid rgba(255,255,255,0.08)',
              color: '#94A3B8',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
              transition: 'all 180ms ease',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
            onMouseEnter={e => {
              e.currentTarget.style.color = '#22D3EE';
              e.currentTarget.style.borderColor = 'rgba(34,211,238,0.30)';
              e.currentTarget.style.background = 'rgba(34,211,238,0.06)';
            }}
            onMouseLeave={e => {
              e.currentTarget.style.color = '#94A3B8';
              e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)';
              e.currentTarget.style.background = 'rgba(255,255,255,0.04)';
            }}
          >
            <ArrowLeft style={{ width: 13, height: 13, flexShrink: 0 }} />
            <span className="hidden sm:inline">Command Center</span>
          </button>

          {/* Divider */}
          <ChevronRight style={{ width: 14, height: 14, color: '#334155', flexShrink: 0 }} />

          {/* Page title with icon */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
            <div
              style={{
                width: 32,
                height: 32,
                borderRadius: '9px',
                background: 'rgba(34,211,238,0.09)',
                border: '1px solid rgba(34,211,238,0.22)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}
            >
              <Shield style={{ width: 15, height: 15, color: '#22D3EE' }} />
            </div>
            <h1
              style={{
                fontFamily: "'Outfit', sans-serif",
                fontSize: '1rem',
                fontWeight: 700,
                color: '#E2E8F0',
                margin: 0,
                letterSpacing: '-0.01em',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {title}
            </h1>
          </div>
        </div>

        {/* Right: User profile */}
        <div style={{ flexShrink: 0 }}>
          <UserProfile user={user} onLogout={onLogout} />
        </div>
      </div>
    </header>
  );
}
