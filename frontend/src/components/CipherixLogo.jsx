import React from 'react';
import { Shield, Lock } from 'lucide-react';

export function CipherixLogo() {
  return (
    <div className="flex flex-col items-center text-center space-y-3 select-none">
      {/* Glowing Shield Icon */}
      <div className="relative group">
        <div className="absolute -inset-1 rounded-2xl bg-gradient-to-r from-[#00f2fe] via-[#7000ff] to-[#00e676] opacity-70 blur-md group-hover:opacity-100 transition duration-500"></div>
        <div className="relative w-16 h-16 rounded-2xl bg-[#0c111c] border border-cyan-500/40 flex items-center justify-center text-cyan-400 shadow-2xl">
          <Shield className="w-9 h-9 stroke-[2.2] text-[#00f2fe]" />
          <Lock className="w-4 h-4 absolute text-purple-400 bottom-3.5 right-3.5" />
        </div>
      </div>

      {/* Main Brand Title & Version */}
      <div className="space-y-1">
        <div className="flex items-center justify-center gap-3">
          <h1 className="text-4xl sm:text-5xl font-extrabold tracking-wider font-outfit bg-gradient-to-r from-[#00f2fe] via-slate-100 to-[#a855f7] bg-clip-text text-transparent drop-shadow-sm">
            CIPHERIX
          </h1>
          <span className="badge-tag badge-cyan text-[11px] font-semibold py-1 px-3 shadow-glow">
            <span className="w-2 h-2 rounded-full bg-[#00e676] animate-pulse mr-1"></span>
            Vault Active v0.1.0
          </span>
        </div>

        {/* Taglines */}
        <p className="text-lg sm:text-xl font-semibold text-slate-200 tracking-wide font-outfit">
          Secure. Private. Intelligent.
        </p>
        <p className="text-xs sm:text-sm text-slate-400 font-medium">
          Your data. Your vault. Your control.
        </p>
      </div>
    </div>
  );
}
