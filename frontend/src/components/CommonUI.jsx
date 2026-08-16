import React from 'react';
import { Loader2, AlertTriangle, Info, CheckCircle2, X } from 'lucide-react';

export function LoadingState({ message = "Loading secure data..." }) {
  return (
    <div className="glass-panel p-8 text-center text-xs text-cyan-400 flex flex-col items-center justify-center space-y-3">
      <Loader2 className="w-7 h-7 animate-spin text-cyan-400" />
      <span>{message}</span>
    </div>
  );
}

export function EmptyState({ title = "No items found", description = "Click the action button above to create or upload items.", actionLabel, onAction }) {
  return (
    <div className="glass-panel p-10 text-center space-y-3 flex flex-col items-center justify-center">
      <div className="w-12 h-12 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400">
        <Info className="w-6 h-6" />
      </div>
      <h3 className="text-sm font-bold text-slate-200">{title}</h3>
      <p className="text-xs text-slate-400 max-w-sm">{description}</p>
      {actionLabel && (
        <button onClick={onAction} className="mt-2 px-4 py-2 rounded-xl bg-cyan-500 text-black font-bold text-xs">
          {actionLabel}
        </button>
      )}
    </div>
  );
}

export function ErrorState({ message, onRetry }) {
  return (
    <div className="glass-panel p-5 border-rose-500/30 bg-rose-500/5 text-xs text-rose-300 flex justify-between items-center">
      <div className="flex items-center gap-2.5">
        <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
        <span>{message || "An unexpected API error occurred."}</span>
      </div>
      {onRetry && (
        <button onClick={onRetry} className="px-3 py-1 rounded-lg bg-rose-500/20 text-rose-300 font-bold border border-rose-500/40 hover:bg-rose-500/30">
          Retry
        </button>
      )}
    </div>
  );
}

export function ConfirmDialog({ isOpen, title, message, confirmLabel = "Delete", onConfirm, onCancel, isDanger = true }) {
  if (!isOpen) return null;
  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="glass-panel max-w-sm w-full p-6 space-y-4 relative border-slate-800">
        <div className="flex justify-between items-center border-b border-slate-800 pb-3">
          <h3 className="text-sm font-bold font-outfit text-slate-100">{title}</h3>
          <button onClick={onCancel} className="text-slate-400 hover:text-slate-100">
            <X className="w-4 h-4" />
          </button>
        </div>
        <p className="text-xs text-slate-400 leading-relaxed">{message}</p>
        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onCancel} className="px-4 py-2 rounded-xl bg-slate-900 text-xs font-semibold text-slate-300 hover:bg-slate-800">
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className={`px-4 py-2 rounded-xl text-xs font-bold ${isDanger ? 'bg-rose-500 text-black hover:bg-rose-400' : 'bg-cyan-500 text-black hover:bg-cyan-400'}`}
          >
            {confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}

export function VaultSelector({ vaults = [], selectedVaultId, onChange, label = "Select Vault" }) {
  return (
    <div className="flex items-center gap-2">
      {label && <label className="text-xs font-bold text-slate-400 uppercase tracking-wider hidden sm:block">{label}:</label>}
      <select
        value={selectedVaultId}
        onChange={(e) => onChange(e.target.value)}
        className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500 max-w-xs"
      >
        {vaults.length === 0 && <option value="">No Vaults Available</option>}
        {vaults.map((v) => (
          <option key={v.vault_id} value={v.vault_id}>
            {v.name} ({v.status})
          </option>
        ))}
      </select>
    </div>
  );
}

export function Toast({ message, type = "success", onClose }) {
  if (!message) return null;
  return (
    <div className={`fixed bottom-6 right-6 z-50 px-4 py-3 rounded-xl border text-xs font-semibold shadow-2xl flex items-center gap-2 animate-bounce ${type === 'success' ? 'bg-emerald-500/10 border-emerald-500/40 text-emerald-300' : 'bg-rose-500/10 border-rose-500/40 text-rose-300'}`}>
      {type === 'success' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <AlertTriangle className="w-4 h-4 text-rose-400" />}
      <span>{message}</span>
      <button onClick={onClose} className="ml-2 text-slate-400 hover:text-slate-100">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}
