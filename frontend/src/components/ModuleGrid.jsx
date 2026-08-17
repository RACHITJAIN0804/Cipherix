import React from 'react';
import { 
  LayoutDashboard, 
  LockKeyhole, 
  FileText, 
  Search, 
  Brain, 
  ShieldCheck, 
  Terminal, 
  History 
} from 'lucide-react';
import { ModuleCard } from './ModuleCard';

export function ModuleGrid({ vaultCount = 2, docCount = 5 }) {
  const modules = [
    {
      title: "Dashboard",
      description: "Comprehensive system metrics, active vault overview, and security radar.",
      icon: LayoutDashboard,
      badge: "Overview",
      accent: "cyan",
      route: "/dashboard",
    },
    {
      title: "Vaults",
      description: "Create and manage Argon2id derived secure document vaults.",
      icon: LockKeyhole,
      badge: vaultCount,
      accent: "green",
      route: "/vaults",
    },
    {
      title: "Documents",
      description: "Upload, store, and stream AES-256-GCM encrypted document blobs.",
      icon: FileText,
      badge: docCount,
      accent: "purple",
      route: "/documents",
    },
    {
      title: "AI Search",
      description: "Execute vault-isolated semantic search using SentenceTransformers embeddings.",
      icon: Search,
      badge: "Vector",
      accent: "blue",
      route: "/search",
    },
    {
      title: "AI Assistant",
      description: "Ask questions grounded in vault documents via local Ollama LLM.",
      icon: Brain,
      badge: "Ollama",
      accent: "green",
      route: "/assistant",
    },
    {
      title: "Integrity",
      description: "3-tier document verification matching disk ciphertext against local blockchain.",
      icon: ShieldCheck,
      badge: "Local Chain",
      accent: "amber",
      route: "/integrity",
    },
    {
      title: "Computer Access",
      description: "Controlled local workspace action executor protected by PathGuard isolation.",
      icon: Terminal,
      badge: "Guarded",
      accent: "blue",
      route: "/computer-access",
    },
    {
      title: "Activity Log",
      description: "Structured, persistent audit logs guaranteed zero-knowledge of secrets.",
      icon: History,
      badge: "Audit",
      accent: "cyan",
      route: "/activity",
    },
  ];

  return (
    <div className="cipherix-module-grid">
      {modules.map((mod) => (
        <ModuleCard key={mod.title} {...mod} />
      ))}
    </div>
  );
}
