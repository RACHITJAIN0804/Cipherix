import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { History, ShieldCheck, Filter, RefreshCw } from 'lucide-react';

const CATEGORIES = ['ALL', 'AUTH', 'VAULT', 'BLOCKCHAIN', 'COMPUTERACCESS'];

function categoryColor(cat) {
  switch ((cat || '').toUpperCase()) {
    case 'AUTH': return 'badge-blue';
    case 'VAULT': return 'badge-cyan';
    case 'BLOCKCHAIN': return 'badge-amber';
    case 'COMPUTERACCESS': return 'badge-purple';
    default: return 'badge-cyan';
  }
}

export function ActivityLogView({ user, onLogout }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    setError('');
    try {
      const data = await CipherixAPI.request('/computer-access/audit-logs');
      const rawList = Array.isArray(data) ? data : [];
      const normalized = rawList.map((log) => ({
        id: log.id,
        timestamp: log.created_at,
        category: 'ComputerAccess',
        action: log.action || 'System Event',
        status: (log.result_status || 'SUCCESS').toUpperCase(),
        details:
          log.details_json ||
          log.relative_path ||
          (log.vault_id ? `Vault: ${log.vault_id}` : 'Access event recorded'),
      }));
      setLogs(normalized);
    } catch (err) {
      setError('Failed to fetch audit logs: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchLogs(); }, []);

  const filteredLogs = logs.filter((log) =>
    categoryFilter === 'ALL' || (log.category || '').toUpperCase() === categoryFilter.toUpperCase()
  );

  const selectStyle = {
    background: 'var(--bg-input)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '10px',
    padding: '7px 32px 7px 10px',
    fontSize: '0.8rem',
    color: 'var(--text-primary)',
    cursor: 'pointer',
    outline: 'none',
    transition: 'border-color 160ms ease',
    appearance: 'none',
    backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%2364748B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpolyline points='6 9 12 15 18 9'%3E%3C/polyline%3E%3C/svg%3E\")",
    backgroundRepeat: 'no-repeat',
    backgroundPosition: 'right 8px center',
  };

  return (
    <PageLayout title="Activity Log & Audit Stream" user={user} onLogout={onLogout}>
      {}
      <PageHeader
        icon={History}
        iconColor="text-cyan-400"
        title="System Activity & Audit Log Stream"
        description="Structured audit events across authentication, vault key operations, document access, and computer actions."
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter style={{ width: 13, height: 13, color: 'var(--text-muted)', flexShrink: 0 }} />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            style={selectStyle}
            onFocus={e => (e.currentTarget.style.borderColor = 'rgba(34,211,238,0.40)')}
            onBlur={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,0.10)')}
          >
            <option value="ALL">All Categories</option>
            <option value="AUTH">Authentication</option>
            <option value="VAULT">Vault</option>
            <option value="BLOCKCHAIN">Blockchain</option>
            <option value="COMPUTERACCESS">Computer Access</option>
          </select>
        </div>
        <span className="badge-tag badge-emerald">
          <ShieldCheck style={{ width: 12, height: 12 }} />
          <span>Zero Secrets Logged</span>
        </span>
        <button
          onClick={fetchLogs}
          className="btn btn-secondary"
          style={{ fontSize: '0.78rem', padding: '7px 12px' }}
          title="Refresh logs"
        >
          <RefreshCw style={{ width: 13, height: 13, ...(loading ? { animation: 'spin 1s linear infinite' } : {}) }} />
          Refresh
        </button>
      </PageHeader>

      {error && <ErrorState message={error} onRetry={fetchLogs} />}

      {loading ? (
        <LoadingState message="Fetching system audit stream..." />
      ) : filteredLogs.length === 0 ? (
        <EmptyState
          title="No Audit Events Recorded"
          description="No activity logs match the selected filter. Events will appear here as system operations are performed."
        />
      ) : (
        <div className="glass-panel" style={{ padding: 0, overflow: 'hidden' }}>
          {}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '12px 20px',
              borderBottom: '1px solid rgba(255,255,255,0.06)',
              background: 'rgba(0,0,0,0.25)',
            }}
          >
            <span style={{ fontSize: '0.78125rem', color: 'var(--text-muted)', fontWeight: 600 }}>
              {filteredLogs.length} event{filteredLogs.length !== 1 ? 's' : ''} recorded
            </span>
            {categoryFilter !== 'ALL' && (
              <span className={`badge-tag ${categoryColor(categoryFilter)}`}>
                {categoryFilter}
              </span>
            )}
          </div>

          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Category</th>
                  <th>Action</th>
                  <th>Status</th>
                  <th>Event Details</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, index) => (
                  <tr key={log.id || index}>
                    <td>
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.6875rem',
                          color: 'var(--text-muted)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {new Date(log.timestamp).toLocaleString()}
                      </span>
                    </td>
                    <td>
                      <span className={`badge-tag ${categoryColor(log.category)}`} style={{ fontSize: '0.6875rem' }}>
                        {log.category || 'System'}
                      </span>
                    </td>
                    <td>
                      <span
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.78125rem',
                          color: 'var(--accent-cyan)',
                          fontWeight: 600,
                        }}
                      >
                        {log.action}
                      </span>
                    </td>
                    <td>
                      <span className={`badge-tag ${log.status === 'SUCCESS' ? 'badge-emerald' : 'badge-rose'}`}>
                        {log.status || 'SUCCESS'}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: '0.78125rem', color: 'var(--text-secondary)' }}>
                        {log.details}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
