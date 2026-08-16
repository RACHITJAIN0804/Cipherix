import React, { useState } from 'react';
import { User, ChevronDown, ShieldCheck, LogOut, CheckCircle2 } from 'lucide-react';

export function UserProfile({ user, onLogout }) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const username = user?.username || localStorage.getItem("cipherix_username") || "rachit_admin";

  return (
    <div className="relative z-30">
      <div 
        onClick={() => setDropdownOpen(!dropdownOpen)}
        className="glass-panel px-4 py-2.5 flex items-center gap-3 cursor-pointer hover:border-cyan-500/50 transition-all select-none group"
      >
        <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 to-purple-500/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold group-hover:scale-105 transition-transform">
          <User className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="text-left hidden sm:block">
          <div className="text-xs font-bold text-slate-100 flex items-center gap-1.5">
            <span>{username}</span>
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-[11px] text-slate-400 font-medium flex items-center gap-1">
            <span>Administrator</span>
          </div>
        </div>
        <ChevronDown className={`w-4 h-4 text-slate-400 transition-transform duration-200 ${dropdownOpen ? 'rotate-180' : ''}`} />
      </div>

      {/* Dropdown Menu */}
      {dropdownOpen && (
        <div className="absolute right-0 mt-2 w-56 rounded-xl bg-[#0c111c] border border-slate-800 shadow-2xl p-2 z-50 text-xs space-y-1 backdrop-blur-xl">
          <div className="px-3 py-2 border-b border-slate-800/80 text-slate-400">
            <div className="text-slate-200 font-bold">{username}</div>
            <div className="text-[10px] text-emerald-400 flex items-center gap-1 mt-0.5">
              <CheckCircle2 className="w-3 h-3" />
              <span>JWT Session Active</span>
            </div>
          </div>
          <button 
            onClick={() => {
              setDropdownOpen(false);
              if (onLogout) onLogout();
            }}
            className="w-full text-left px-3 py-2 text-rose-400 hover:bg-rose-500/10 rounded-lg flex items-center gap-2 font-medium transition-colors"
          >
            <LogOut className="w-4 h-4" />
            <span>End Session (Logout)</span>
          </button>
        </div>
      )}
    </div>
  );
}
