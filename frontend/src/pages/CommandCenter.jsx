import React, { useState, useEffect } from 'react';
import { CipherixLogo } from '../components/CipherixLogo';
import { UserProfile } from '../components/UserProfile';
import { ModuleGrid } from '../components/ModuleGrid';
import { SystemSection } from '../components/SystemCard';
import { StatusBar } from '../components/StatusBar';
import { PageTransition } from '../components/PageTransition';
import { CipherixAPI } from '../api';

export function CommandCenter({ user, onLogout }) {
  const [stats, setStats] = useState({ vaultCount: 2, docCount: 5 });

  useEffect(() => {
    async function loadStats() {
      try {
        const vaults = await CipherixAPI.request('/vaults');
        const vCount = Array.isArray(vaults) ? vaults.length : 2;
        let dCount = 5;
        if (Array.isArray(vaults) && vaults.length > 0) {
          const docs = await CipherixAPI.request(`/vaults/${vaults[0].vault_id}/documents`);
          if (Array.isArray(docs)) dCount = docs.length;
        }
        setStats({ vaultCount: vCount, docCount: dCount });
      } catch (e) {
        console.warn("CommandCenter stats load fallback:", e);
      }
    }
    loadStats();
  }, []);

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12] text-slate-100 relative overflow-x-hidden selection:bg-cyan-500 selection:text-black">
        {/* Top Floating User Profile */}
        <div className="absolute top-6 right-6 sm:right-10 z-30">
          <UserProfile user={user} onLogout={onLogout} />
        </div>

        {/* Centered Command Center Container */}
        <div className="command-center-container flex flex-col items-center space-y-8 md:space-y-12 lg:space-y-14">
          
          {/* Header Section */}
          <div className="pt-4 pb-2 w-full max-w-2xl">
            <CipherixLogo />
          </div>

          {/* Core Modules Grid */}
          <div className="w-full">
            <ModuleGrid vaultCount={stats.vaultCount} docCount={stats.docCount} />
          </div>

          {/* System Section */}
          <div className="w-full">
            <SystemSection />
          </div>

          {/* Bottom Status Bar */}
          <div className="w-full">
            <StatusBar username={user?.username || "rachit_admin"} />
          </div>

        </div>
      </div>
    </PageTransition>
  );
}
