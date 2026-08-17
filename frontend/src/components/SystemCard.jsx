import React from 'react';
import { Settings, KeyRound } from 'lucide-react';
import { ModuleCard } from './ModuleCard';

export function SystemSection() {
  const systemModules = [
    {
      title: "Settings",
      description: "Configure your preferences, environment variables, and system defaults.",
      icon: Settings,
      badge: "Config",
      accent: "slate",
      route: "/settings",
    },
    {
      title: "Security & Keys",
      description: "Manage your cryptographic keys, Argon2id settings, and 16-word BIP-39 recovery seed.",
      icon: KeyRound,
      badge: "Cryptographic",
      accent: "rose",
      route: "/security",
    },
  ];

  return (
    <div className="space-y-6 w-full pt-10">
      {/* Centered SYSTEM Section Header */}
      <div className="flex items-center justify-center gap-4">
        <div className="h-[1px] w-24 bg-gradient-to-r from-transparent to-slate-700"></div>
        <h2 className="text-xs font-extrabold uppercase tracking-widest text-slate-400 font-outfit">
          SYSTEM
        </h2>
        <div className="h-[1px] w-24 bg-gradient-to-l from-transparent to-slate-700"></div>
      </div>

      {/* 2 Column System Grid */}
      <div className="cipherix-system-grid">
        {systemModules.map((mod) => (
          <ModuleCard key={mod.title} {...mod} />
        ))}
      </div>
    </div>
  );
}
