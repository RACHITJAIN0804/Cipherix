import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { History, ShieldCheck, Filter } from 'lucide-react';

export function ActivityLogView({ user, onLogout }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('ALL');

  const fetchLogs = async () => {
    setLoading(true);
    setError('');
    try {
      const secLogs = await CipherixAPI.request('/security/audit-logs');
      const compLogs = await CipherixAPI.request('/computer-access/audit');

      const combined = [
        ...(Array.isArray(secLogs) ? secLogs : []),
        ...(Array.isArray(compLogs) ? compLogs : []),
      ];

      setLogs(combined);
    } catch (err) {
      setError('Failed to fetch audit logs: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLogs();
  }, []);

  const filteredLogs = logs.filter((log) => {
    if (categoryFilter === 'ALL') return true;
    return (log.category || '').toUpperCase() === categoryFilter.toUpperCase();
  });

  return (
    <PageLayout title="Activity Log & Audit Stream" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={History}
        iconColor="text-cyan-400"
        title="System Activity & Audit Log Stream"
        description="Structured audit events across authentication, vault key operations, document access, and computer actions."
      >
        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400 flex-shrink-0" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors"
          >
            <option value="ALL">All Categories</option>
            <option value="AUTH">Authentication</option>
            <option value="VAULT">Vault</option>
            <option value="BLOCKCHAIN">Blockchain</option>
            <option value="COMPUTERACCESS">Computer Access</option>
          </select>
        </div>
        <span className="badge-tag badge-emerald">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Zero Secrets Logged</span>
        </span>
      </PageHeader>

      {error && <ErrorState message={error} onRetry={fetchLogs} />}

      {loading ? (
        <LoadingState message="Fetching system audit stream..." />
      ) : filteredLogs.length === 0 ? (
        <EmptyState title="No Audit Events Recorded" description="No activity logs match the selected filter." />
      ) : (
        <div className="glass-panel overflow-hidden p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="bg-slate-900/80 text-slate-400 uppercase font-bold text-[11px] border-b border-slate-800">
                  <th className="p-4">Timestamp</th>
                  <th className="p-4">Category</th>
                  <th className="p-4">Action</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Event Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log, index) => (
                  <tr key={log.id || index} className="hover:bg-slate-900/40 transition-colors">
                    <td className="p-4 text-slate-400 font-mono text-[11px]">
                      {new Date(log.timestamp).toLocaleString()}
                    </td>
                    <td className="p-4 font-semibold text-slate-100">{log.category || 'System'}</td>
                    <td className="p-4 text-cyan-400 font-mono">{log.action}</td>
                    <td className="p-4">
                      <span className={`badge-tag ${log.status === 'SUCCESS' ? 'badge-emerald' : 'badge-rose'}`}>
                        {log.status || 'SUCCESS'}
                      </span>
                    </td>
                    <td className="p-4 text-slate-300 text-xs">{log.details}</td>
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
