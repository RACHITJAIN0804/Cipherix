import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { CipherixAPI } from '../api';
import { Vault, ShieldAlert, Boxes, ShieldCheck, Activity, Lock, RefreshCw } from 'lucide-react';

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
    <PageTransition>
      <div className="min-h-screen bg-[#070a10]">
        <TopNavBar title="Dashboard Overview" user={user} onLogout={onLogout} />

        <main className="max-w-7xl mx-auto p-6 space-y-6">
          {/* Stat Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
            <div className="glass-panel p-5 relative overflow-hidden">
              <div className="flex justify-between items-start">
                <div>
                  <div className="text-xs text-slate-400 font-bold uppercase tracking-wider">ACTIVE VAULTS</div>
                  <div className="text-3xl font-extrabold font-outfit mt-1 text-slate-100">{vaults.length}</div>
                </div>
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
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
                  <div class="text-xs text-slate-400 font-bold uppercase tracking-wider">ENCRYPTED DOCUMENTS</div>
                  <div className="text-3xl font-extrabold font-outfit mt-1 text-slate-100">5</div>
                </div>
                <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center justify-center">
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
                <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center">
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
                <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center">
                  <Activity className="w-5 h-5" />
                </div>
              </div>
              <div className="mt-4 flex items-center gap-2 text-xs text-emerald-400 font-medium">
                <span>0 Leaks • Zero-Knowledge</span>
              </div>
            </div>
          </div>

          {/* Vault Status List */}
          <div className="glass-panel p-6 space-y-4">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-lg font-bold font-outfit text-slate-100 flex items-center gap-2">
                <Vault className="w-5 h-5 text-cyan-400" />
                <span>Vault Status Overview</span>
              </h3>
              <button onClick={loadData} className="px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs font-semibold text-slate-300 hover:text-cyan-400 flex items-center gap-1.5">
                <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </button>
            </div>

            <div className="space-y-3">
              {vaults.map((v) => (
                <div key={v.vault_id} className="p-4 rounded-xl bg-slate-900/60 border border-slate-800/80 flex justify-between items-center text-xs">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
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
        </main>
      </div>
    </PageTransition>
  );
}
