import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { CipherixAPI } from '../api';
import { Vault, ShieldAlert, Boxes, ShieldCheck, Activity, Lock, RefreshCw, LayoutDashboard } from 'lucide-react';

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

  return (
    <PageLayout title="Dashboard Overview" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={LayoutDashboard}
        iconColor="text-cyan-400"
        title="Dashboard Overview"
        description="Real-time system metrics, vault status, and security posture monitoring."
      >
        <button
          onClick={loadData}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-cyan-400 hover:border-cyan-500/40 transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </PageHeader>

      {/* Stat Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        <div className="glass-panel p-5 relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider">ACTIVE VAULTS</div>
              <div className="text-3xl font-extrabold font-outfit mt-1 text-slate-100">{vaults.length}</div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0">
              <Vault className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2 text-xs text-emerald-400 font-medium">
            <Lock className="w-3.5 h-3.5" />
            <span>Argon2id Key Derived</span>
          </div>
        </div>

        <div className="glass-panel p-5 relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider">ENCRYPTED DOCUMENTS</div>
              <div className="text-3xl font-extrabold font-outfit mt-1 text-slate-100">5</div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2 text-xs text-purple-400 font-medium">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>AES-256-GCM Ciphertext</span>
          </div>
        </div>

        <div className="glass-panel p-5 relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider">BLOCKCHAIN ANCHORS</div>
              <div className="text-3xl font-extrabold font-outfit mt-1 text-slate-100">5</div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center flex-shrink-0">
              <Boxes className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2 text-xs text-amber-400 font-medium">
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Tamper-Proof Ledger</span>
          </div>
        </div>

        <div className="glass-panel p-5 relative overflow-hidden">
          <div className="flex justify-between items-start">
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider">SECURITY SCORE</div>
              <div className="text-3xl font-extrabold font-outfit mt-1 text-emerald-400">100%</div>
            </div>
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center flex-shrink-0">
              <Activity className="w-5 h-5" />
            </div>
          </div>
          <div className="mt-4 flex items-center gap-2 text-xs text-emerald-400 font-medium">
            <span>0 Leaks • Zero-Knowledge</span>
          </div>
        </div>
      </div>

      {/* Vault Status List */}
      <div className="glass-panel p-6">
        <div className="flex justify-between items-center border-b border-slate-800 pb-4 mb-4">
          <h3 className="text-base font-bold font-outfit text-slate-100 flex items-center gap-2">
            <Vault className="w-5 h-5 text-cyan-400" />
            <span>Vault Status Overview</span>
          </h3>
        </div>

        <div className="flex flex-col gap-3">
          {vaults.length === 0 && !loading && (
            <p className="text-xs text-slate-400 py-4 text-center">No vaults found. Create one in the Vaults module.</p>
          )}
          {vaults.map((v) => (
            <div key={v.vault_id} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex justify-between items-center text-xs">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center flex-shrink-0">
                  <Vault className="w-5 h-5" />
                </div>
                <div>
                  <div className="font-bold text-slate-100 text-sm">{v.name}</div>
                  <div className="text-slate-400 font-mono">ID: {v.vault_id}</div>
                </div>
              </div>
              <span className={`badge-tag ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}`}>
                {v.status.toUpperCase()}
              </span>
            </div>
          ))}
        </div>
      </div>
    </PageLayout>
  );
}
