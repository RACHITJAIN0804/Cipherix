import React from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { Settings } from 'lucide-react';

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

      {/* Settings Cards */}
      <div className="glass-panel p-6 flex flex-col gap-6">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">APP ENVIRONMENT</div>
            <div className="font-mono text-cyan-400 font-bold text-sm">DEVELOPMENT</div>
            <div className="text-slate-400 text-[10px]">Production configuration guard active</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">JWT EXPIRATION</div>
            <div className="font-mono text-purple-400 font-bold text-sm">30 Minutes</div>
            <div className="text-slate-400 text-[10px]">Refresh token rotation enabled</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">BLOCKCHAIN NETWORK</div>
            <div className="font-mono text-amber-400 font-bold text-sm">local-development</div>
            <div className="text-slate-400 text-[10px]">Deterministic HMAC notarization</div>
          </div>

          <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 flex flex-col gap-1">
            <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">LOCAL LLM BACKEND</div>
            <div className="font-mono text-emerald-400 font-bold text-sm">Ollama (llama3.2:1b)</div>
            <div className="text-slate-400 text-[10px]">Zero-knowledge local inference</div>
          </div>
        </div>

        <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 flex flex-col gap-3 text-xs">
          <h3 className="font-bold text-slate-200">Rate Throttling Protections</h3>
          <p className="text-slate-400">
            Sliding window rate limiters enforce security against brute-force attacks:
          </p>
          <ul className="list-disc list-inside text-slate-300 flex flex-col gap-1 font-mono text-[11px]">
            <li>
              Auth Endpoints (/login, /register):{' '}
              <strong>10 requests / minute</strong>
            </li>
            <li>
              Expensive Endpoints (/search, /rag, /blockchain, /computer-access):{' '}
              <strong>30 requests / minute</strong>
            </li>
          </ul>
        </div>
      </div>
    </PageLayout>
  );
}
