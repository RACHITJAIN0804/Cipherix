import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Terminal, Play, FolderOpen, ShieldCheck, ShieldOff, Folder } from 'lucide-react';

export function ComputerAccessView({ user, onLogout }) {
  const [enabled, setEnabled] = useState(false);
  const [workspaceRoot, setWorkspaceRoot] = useState('CIPHERIX_WORKSPACE');
  const [allowlist, setAllowlist] = useState(['list_directory', 'read_text_file', 'create_text_file']);
  const [selectedAction, setSelectedAction] = useState('list_directory');
  const [pathParam, setPathParam] = useState('.');
  const [contentParam, setContentParam] = useState('');
  const [approvedParam, setApprovedParam] = useState(true);
  const [actionResult, setActionResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const statusRes = await CipherixAPI.request('/computer-access/status');
      setEnabled(statusRes.enabled ?? false);
      if (statusRes.workspace_root) setWorkspaceRoot(statusRes.workspace_root);
      if (statusRes.actions_allowlist) setAllowlist(statusRes.actions_allowlist);
      const auditRes = await CipherixAPI.request('/computer-access/audit');
      setAuditLogs(Array.isArray(auditRes) ? auditRes : []);
    } catch (err) { console.warn(err); }
    finally { setLoading(false); }
  };

  useEffect(() => { fetchStatus(); }, []);

  const handleToggle = async () => {
    try {
      const res = await CipherixAPI.request('/computer-access/toggle', {
        method: 'POST',
        body: JSON.stringify({ enabled: !enabled }),
      });
      setEnabled(res.enabled ?? !enabled);
    } catch (err) { alert('Toggle Error: ' + err.message); }
  };

  const handleExecuteAction = async (e) => {
    e.preventDefault();
    if (!enabled) {
      alert('Computer Access is DISABLED. Toggle Master Access to ENABLE before executing actions.');
      return;
    }
    const params = { path: pathParam };
    if (selectedAction === 'create_text_file') params.content = contentParam;
    setError('');
    try {
      const res = await CipherixAPI.request('/computer-access/action', {
        method: 'POST',
        body: JSON.stringify({ action: selectedAction, parameters: params, approved: approvedParam }),
      });
      setActionResult(res);
      fetchStatus();
    } catch (err) { setError('Action Execution Rejected: ' + err.message); }
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

  const selectStyle = {
    ...inputStyle,
    appearance: 'none',
    backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E\")",
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 12px center',
    paddingRight: '36px',
    cursor: 'pointer',
  };

  return (
    <PageLayout title="Controlled Computer Access" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={Terminal}
        iconColor="text-blue-400"
        title="Controlled Local-Computer Access System"
        description="Safely executes allowlisted filesystem actions strictly bounded inside CIPHERIX_WORKSPACE. Disabled by default."
      >
        <button
          onClick={handleToggle}
          className="btn"
          style={{
            background: enabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)',
            border: `1px solid ${enabled ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'}`,
            color: enabled ? 'var(--accent-emerald)' : '#f87171',
            transition: 'all 160ms',
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = enabled ? 'rgba(16,185,129,0.25)' : 'rgba(239,68,68,0.25)';
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = enabled ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)';
          }}
        >
          {enabled
            ? <ShieldCheck style={{ width: 14, height: 14 }} />
            : <ShieldOff style={{ width: 14, height: 14 }} />
          }
          MASTER ACCESS: {enabled ? 'ENABLED' : 'DISABLED'}
        </button>
      </PageHeader>

      {error && <ErrorState message={error} />}

      {}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '14px' }}>
        {[
          {
            label: 'Workspace Boundary',
            value: workspaceRoot,
            valueColor: 'var(--accent-cyan)',
            note: 'PathGuard traversal strictly blocked',
            icon: Folder,
          },
          {
            label: 'Action Allowlist',
            value: allowlist.join(' • '),
            valueColor: 'var(--accent-purple)',
            note: 'Arbitrary command execution blocked',
            icon: ShieldCheck,
          },
          {
            label: 'Audit Compliance',
            value: 'Zero Secrets Logged',
            valueColor: 'var(--accent-emerald)',
            note: 'Structured Audit Trail Stream',
            icon: ShieldCheck,
          },
        ].map(({ label, value, valueColor, note, icon: Icon }) => (
          <div
            key={label}
            className="glass-panel"
            style={{ padding: '18px', display: 'flex', flexDirection: 'column', gap: '8px' }}
          >
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>{label}</div>
            <div
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.825rem',
                fontWeight: 700,
                color: valueColor,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              title={value}
            >
              {value}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{note}</div>
          </div>
        ))}
      </div>

      {}
      <div
        className="glass-panel"
        style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px', borderColor: 'rgba(59,130,246,0.15)' }}
      >
        <h3 className="section-title">
          <Play style={{ width: 15, height: 15, color: 'var(--accent-blue)' }} />
          Execute Allowlisted Action
        </h3>

        <form onSubmit={handleExecuteAction} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
            <div>
              <label className="form-label">Action Name</label>
              <select
                value={selectedAction}
                onChange={(e) => setSelectedAction(e.target.value)}
                style={selectStyle}
                onFocus={e => { e.target.style.borderColor = 'rgba(59,130,246,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.08)'; }}
                onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
              >
                {allowlist.map((act) => (
                  <option key={act} value={act}>{act}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="form-label">Target Relative Path</label>
              <input
                type="text"
                value={pathParam}
                onChange={(e) => setPathParam(e.target.value)}
                placeholder="e.g. 'notes/todo.txt' or '.'"
                style={inputStyle}
                onFocus={e => { e.target.style.borderColor = 'rgba(59,130,246,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.08)'; }}
                onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
              />
            </div>
            <div style={{ display: 'flex', alignItems: 'flex-end' }}>
              <button
                type="submit"
                className="btn"
                style={{
                  width: '100%',
                  background: 'var(--accent-blue)',
                  color: '#050a12',
                  boxShadow: '0 4px 14px rgba(59,130,246,0.22)',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = '#60a5fa'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-blue)'; e.currentTarget.style.transform = 'translateY(0)'; }}
              >
                <Play style={{ width: 13, height: 13 }} />
                Execute Action
              </button>
            </div>
          </div>

          {selectedAction === 'create_text_file' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.06)' }}>
              <div>
                <label className="form-label">File Content</label>
                <textarea
                  value={contentParam}
                  onChange={(e) => setContentParam(e.target.value)}
                  placeholder="Text content to write inside workspace file..."
                  rows={4}
                  style={{ ...inputStyle, resize: 'vertical', minHeight: '80px' }}
                  onFocus={e => { e.target.style.borderColor = 'rgba(59,130,246,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.08)'; }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                />
              </div>
              <label
                style={{ display: 'flex', alignItems: 'center', gap: '10px', cursor: 'pointer' }}
              >
                <input
                  type="checkbox"
                  id="approved-check"
                  checked={approvedParam}
                  onChange={(e) => setApprovedParam(e.target.checked)}
                  style={{ accentColor: 'var(--accent-blue)', width: 16, height: 16, cursor: 'pointer' }}
                />
                <span style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
                  Explicit User Approval Confirmed
                </span>
              </label>
            </div>
          )}
        </form>

        {}
        {actionResult && (
          <div
            style={{
              padding: '16px',
              borderRadius: '10px',
              background: 'rgba(0,0,0,0.40)',
              border: '1px solid rgba(255,255,255,0.07)',
              display: 'flex',
              flexDirection: 'column',
              gap: '10px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.8125rem', fontWeight: 700, color: 'var(--accent-emerald)' }}>
                Action Result ({actionResult.status})
              </span>
              <span
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.6875rem',
                  color: 'var(--text-muted)',
                }}
              >
                ID: {actionResult.action_id}
              </span>
            </div>
            <pre
              style={{
                fontFamily: "'JetBrains Mono', monospace",
                fontSize: '0.8rem',
                color: 'var(--accent-cyan)',
                padding: '12px 14px',
                background: 'rgba(0,0,0,0.50)',
                borderRadius: '8px',
                overflow: 'auto',
                margin: 0,
                lineHeight: 1.6,
              }}
            >
              {JSON.stringify(actionResult.result, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </PageLayout>
  );
}
