import React from 'react';
import { ShieldCheck, User, Clock, Activity } from 'lucide-react';

export function StatusBar({ username = "rachit_admin", lastLogin = "Active Now" }) {
  return (
    <div className="w-full max-w-4xl mx-auto pt-8">
      <div className="glass-panel p-4 flex flex-wrap items-center justify-between gap-4 text-xs">
        {/* JWT Auth Status */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">JWT Authentication</div>
            <div className="font-semibold text-slate-200">Secure Session</div>
          </div>
        </div>

        {/* User Info */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400 flex items-center justify-center">
            <User className="w-4 h-4 text-purple-400" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Authenticated User</div>
            <div className="font-semibold text-slate-200">{username}</div>
          </div>
        </div>

        {/* Last Login */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-400 flex items-center justify-center">
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">Last Session Login</div>
            <div className="font-semibold text-slate-200">{lastLogin}</div>
          </div>
        </div>

        {/* System Health */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 flex items-center justify-center">
            <Activity className="w-4 h-4 text-emerald-400" />
          </div>
          <div>
            <div className="text-[10px] uppercase font-bold text-slate-400">System Status</div>
            <div className="font-semibold text-emerald-400 flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
              <span>Healthy & Guarded</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
