import React from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { Settings, Shield, Cpu, Lock, Key, Sliders } from 'lucide-react';

export function SettingsView({ user, onLogout }) {
  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12]">
        <TopNavBar title="Settings & Preferences" user={user} onLogout={onLogout} />

        <main className="max-w-[1400px] mx-auto p-6 space-y-6">
          <div className="glass-panel p-6 space-y-6">
            <h2 className="text-xl font-bold font-outfit text-slate-100 flex items-center gap-2">
              <Settings className="w-5 h-5 text-slate-400" />
              <span>System Configuration & Preferences</span>
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">APP ENVIRONMENT</div>
                <div className="font-mono text-cyan-400 font-bold text-sm">DEVELOPMENT</div>
                <div className="text-slate-400 text-[10px]">Production configuration guard active</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">JWT EXPIRATION</div>
                <div className="font-mono text-purple-400 font-bold text-sm">30 Minutes</div>
                <div className="text-slate-400 text-[10px]">Refresh token rotation enabled</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">BLOCKCHAIN NETWORK</div>
                <div className="font-mono text-amber-400 font-bold text-sm">local-development</div>
                <div className="text-slate-400 text-[10px]">Deterministic HMAC notarization</div>
              </div>

              <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-1">
                <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">LOCAL LLM BACKEND</div>
                <div className="font-mono text-emerald-400 font-bold text-sm">Ollama (llama3.2:1b)</div>
                <div className="text-slate-400 text-[10px]">Zero-knowledge local inference</div>
              </div>
            </div>

            <div className="p-5 rounded-xl bg-slate-900/40 border border-slate-800 space-y-3 text-xs">
              <h3 className="font-bold text-slate-200">Rate Throttling Protections</h3>
              <p className="text-slate-400">Sliding window rate limiters enforce security against brute-force attacks:</p>
              <ul className="list-disc list-inside text-slate-300 space-y-1 font-mono text-[11px]">
                <li>Auth Endpoints (/login, /register): <strong>10 requests / minute</strong></li>
                <li>Expensive Endpoints (/search, /rag, /blockchain, /computer-access): <strong>30 requests / minute</strong></li>
              </ul>
            </div>
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
