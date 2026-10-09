import React, { useState, useEffect } from 'react';
import { CipherixLogo } from '../components/CipherixLogo';
import { UserProfile } from '../components/UserProfile';
import { ModuleGrid } from '../components/ModuleGrid';
import { SystemSection } from '../components/SystemCard';
import { StatusBar } from '../components/StatusBar';
import { PageTransition } from '../components/PageTransition';
import { CipherixAPI } from '../api';

export function CommandCenter({ user, onLogout }) {
  const [stats, setStats] = useState({ vaultCount: 0, docCount: 0 });

  useEffect(() => {
    async function loadStats() {
      try {
        const vaults = await CipherixAPI.request('/vaults');
        const vArray = Array.isArray(vaults) ? vaults : [];
        const vCount = vArray.length;
        let dCount = 0;
        if (vArray.length > 0) {
          const docCounts = await Promise.all(
            vArray.map(async (v) => {
              try {
                const docs = await CipherixAPI.request(`/vaults/${v.vault_id}/documents`);
                if (typeof docs?.count === 'number') return docs.count;
                if (Array.isArray(docs?.documents)) return docs.documents.length;
                if (Array.isArray(docs)) return docs.length;
                return typeof v.document_count === 'number' ? v.document_count : 0;
              } catch {
                return typeof v.document_count === 'number' ? v.document_count : 0;
              }
            })
          );
          dCount = docCounts.reduce((acc, c) => acc + c, 0);
        }
        setStats({ vaultCount: vCount, docCount: dCount });
      } catch (e) {
        console.warn("CommandCenter stats load error:", e);
        setStats({ vaultCount: 0, docCount: 0 });
      }
    }
    loadStats();
  }, [user]);

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12] text-slate-100 relative overflow-x-hidden selection:bg-cyan-500 selection:text-black">
        <div className="absolute top-6 right-6 sm:right-10 z-30">
          <UserProfile user={user} onLogout={onLogout} />
        </div>

        <div className="command-center-container flex flex-col items-center space-y-8 md:space-y-12 lg:space-y-14">
          <div className="pt-4 pb-2 w-full max-w-2xl">
            <CipherixLogo />
          </div>

          <div className="w-full">
            <ModuleGrid vaultCount={stats.vaultCount} docCount={stats.docCount} />
          </div>

          <div className="w-full">
            <SystemSection />
          </div>

          <div className="w-full">
            <StatusBar username={user?.username || "rachit_admin"} />
          </div>

        </div>
      </div>
    </PageTransition>
  );
}
