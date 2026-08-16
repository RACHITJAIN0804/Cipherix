import React from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, ArrowLeft } from 'lucide-react';
import { UserProfile } from './UserProfile';

export function TopNavBar({ title, user, onLogout }) {
  const navigate = useNavigate();

  return (
    <header className="sticky top-0 z-40 bg-[#070a10]/80 backdrop-blur-xl border-b border-slate-800/80 px-6 py-3 flex items-center justify-between">
      {/* Left: Back to Command Center & Page Title */}
      <div className="flex items-center gap-4">
        <button
          onClick={() => navigate('/')}
          className="flex items-center gap-2 text-xs font-semibold text-slate-300 hover:text-cyan-400 px-3 py-1.5 rounded-xl bg-slate-900/80 border border-slate-800 hover:border-cyan-500/40 transition-all group"
        >
          <ArrowLeft className="w-4 h-4 transition-transform group-hover:-translate-x-1" />
          <span>Command Center</span>
        </button>

        <div className="h-5 w-[1px] bg-slate-800 hidden sm:block"></div>

        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
            <Shield className="w-4 h-4 text-cyan-400" />
          </div>
          <h1 className="text-lg font-bold font-outfit text-slate-100">{title}</h1>
        </div>
      </div>

      {/* Right: User Profile */}
      <UserProfile user={user} onLogout={onLogout} />
    </header>
  );
}
