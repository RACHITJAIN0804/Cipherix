import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { LoadingState, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Terminal, ShieldAlert, Play, Folder, FileText, CheckCircle2, Lock } from 'lucide-react';

export function ComputerAccessView({ user, onLogout }) {
  const [enabled, setEnabled] = useState(false);
  const [workspaceRoot, setWorkspaceRoot] = useState("CIPHERIX_WORKSPACE");
  const [allowlist, setAllowlist] = useState(["list_directory", "read_text_file", "create_text_file"]);
  const [selectedAction, setSelectedAction] = useState("list_directory");
  const [pathParam, setPathParam] = useState(".");
  const [contentParam, setContentParam] = useState("");
  const [approvedParam, setApprovedParam] = useState(true);
  const [actionResult, setActionResult] = useState(null);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const fetchStatus = async () => {
    setLoading(true);
    try {
      const statusRes = await CipherixAPI.request('/computer-access/status');
      setEnabled(statusRes.enabled ?? false);
      if (statusRes.workspace_root) setWorkspaceRoot(statusRes.workspace_root);
      if (statusRes.actions_allowlist) setAllowlist(statusRes.actions_allowlist);

      const auditRes = await CipherixAPI.request('/computer-access/audit');
      setAuditLogs(Array.isArray(auditRes) ? auditRes : []);
    } catch (err) {
      console.warn(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStatus();
  }, []);

  const handleToggle = async () => {
    try {
      const res = await CipherixAPI.request('/computer-access/toggle', {
        method: 'POST',
        body: JSON.stringify({ enabled: !enabled }),
      });
      setEnabled(res.enabled ?? !enabled);
    } catch (err) {
      alert("Toggle Error: " + err.message);
    }
  };

  const handleExecuteAction = async (e) => {
    e.preventDefault();
    if (!enabled) {
      alert("Computer Access is currently DISABLED. Toggle Master Access to ENABLE before executing actions.");
      return;
    }

    const params = { path: pathParam };
    if (selectedAction === "create_text_file") {
      params.content = contentParam;
    }

    setError("");
    try {
      const res = await CipherixAPI.request('/computer-access/action', {
        method: 'POST',
        body: JSON.stringify({
          action: selectedAction,
          parameters: params,
          approved: approvedParam,
        }),
      });
      setActionResult(res);
      fetchStatus();
    } catch (err) {
      setError("Action Execution Rejected: " + err.message);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#070a10]">
        <TopNavBar title="Controlled Computer Access" user={user} onLogout={onLogout} />

        <main className="max-w-5xl mx-auto p-6 space-y-6">
          <div className="glass-panel p-6 space-y-6 border-blue-500/20">
            <div className="flex flex-wrap justify-between items-center gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-xl font-bold font-outfit text-slate-100 flex items-center gap-2">
                  <Terminal className="w-5 h-5 text-blue-400" />
                  <span>Controlled Local-Computer Access System</span>
                </h2>
                <p className="text-xs text-slate-400">Safely executes allowlisted filesystem actions strictly bounded inside CIPHERIX_WORKSPACE. Disabled by default.</p>
              </div>

              <button
                onClick={handleToggle}
                className={`px-4 py-2 rounded-xl text-xs font-bold transition-all border ${enabled ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40' : 'bg-rose-500/20 text-rose-400 border-rose-500/40'}`}
              >
                MASTER ACCESS: {enabled ? 'ENABLED' : 'DISABLED'}
              </button>
            </div>

            {error && <ErrorState message={error} />}

            {/* PathGuard & Allowlist Status */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold">Workspace Boundary</div>
                <div className="font-mono text-cyan-400 font-bold truncate">{workspaceRoot}</div>
                <div className="text-[10px] text-slate-400">PathGuard traversal strictly blocked</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold">Action Allowlist</div>
                <div className="font-bold text-purple-400">{allowlist.join(" • ")}</div>
                <div className="text-[10px] text-slate-400">Arbitrary command execution blocked</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold">Audit Compliance</div>
                <div className="font-bold text-emerald-400">Zero Secrets Logged</div>
                <div className="text-[10px] text-slate-400">Structured Audit Trail Stream</div>
              </div>
            </div>

            {/* Action Execution Form */}
            <form onSubmit={handleExecuteAction} className="space-y-4 pt-2 border-t border-slate-800">
              <h3 className="text-sm font-bold font-outfit text-slate-100">Execute Allowlisted Action</h3>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div>
                  <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">Action Name</label>
                  <select
                    value={selectedAction}
                    onChange={(e) => setSelectedAction(e.target.value)}
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  >
                    {allowlist.map((act) => (
                      <option key={act} value={act}>{act}</option>
                    ))}
                  </select>
                </div>

                <div>
                  <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">Target Relative Path</label>
                  <input
                    type="text"
                    value={pathParam}
                    onChange={(e) => setPathParam(e.target.value)}
                    placeholder="e.g. 'notes/todo.txt' or '.' "
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                  />
                </div>

                <div className="flex items-end">
                  <button
                    type="submit"
                    className="w-full px-4 py-2 rounded-xl bg-blue-500 text-black font-bold text-xs flex items-center justify-center gap-2 hover:bg-blue-400 transition-colors"
                  >
                    <Play className="w-3.5 h-3.5" />
                    <span>Execute Action</span>
                  </button>
                </div>
              </div>

              {selectedAction === "create_text_file" && (
                <div className="space-y-3 pt-2">
                  <div>
                    <label className="block text-[10px] font-bold uppercase text-slate-400 mb-1">File Content</label>
                    <textarea
                      value={contentParam}
                      onChange={(e) => setContentParam(e.target.value)}
                      placeholder="Text content to write inside workspace file..."
                      className="w-full h-20 bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs text-slate-100 focus:outline-none focus:border-blue-500"
                    />
                  </div>

                  <div className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      id="approved-check"
                      checked={approvedParam}
                      onChange={(e) => setApprovedParam(e.target.checked)}
                      className="accent-blue-500"
                    />
                    <label htmlFor="approved-check" className="text-xs text-slate-300 font-semibold cursor-pointer">
                      Explicit User Approval Confirmed
                    </label>
                  </div>
                </div>
              )}
            </form>

            {/* Result Box */}
            {actionResult && (
              <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 space-y-2 text-xs">
                <div className="flex justify-between items-center">
                  <span className="font-bold text-emerald-400">Action Result ({actionResult.status})</span>
                  <span className="font-mono text-[10px] text-slate-500">ID: {actionResult.action_id}</span>
                </div>
                <pre className="font-mono text-cyan-300 p-3 bg-black rounded-lg text-[11px] overflow-x-auto">
                  {JSON.stringify(actionResult.result, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
