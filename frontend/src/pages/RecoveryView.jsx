import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { LifeBuoy, ShieldAlert, Sparkles, Check, KeyRound, Copy } from 'lucide-react';

export function RecoveryView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState("");
  
  // Seed Generator state
  const [generatedSeed, setGeneratedSeed] = useState("");
  const [copied, setCopied] = useState(false);
  
  // Verify Seed state
  const [candidateSeed, setCandidateSeed] = useState("");
  const [verifyResult, setVerifyResult] = useState(null);

  // Vault Recovery state
  const [recoverySeed, setRecoverySeed] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [recoverySuccess, setRecoverySuccess] = useState("");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadVaults() {
      try {
        const data = await CipherixAPI.request('/vaults');
        const vList = Array.isArray(data) ? data : [];
        setVaults(vList);
        if (vList.length > 0 && !selectedVaultId) {
          setSelectedVaultId(vList[0].vault_id);
        }
      } catch (err) {
        console.warn(err);
      }
    }
    loadVaults();
  }, []);

  const handleGenerateSeed = async () => {
    if (!selectedVaultId) return;
    setLoading(true);
    setError("");
    try {
      const res = await CipherixAPI.request(`/vaults/${selectedVaultId}/recovery-seed`, {
        method: 'POST',
      });
      setGeneratedSeed(res.seed || "");
    } catch (err) {
      setError("Seed Generation Error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleVerifySeed = async (e) => {
    e.preventDefault();
    if (!selectedVaultId || !candidateSeed.trim()) return;
    setLoading(true);
    setError("");
    try {
      const res = await CipherixAPI.request(`/vaults/${selectedVaultId}/recovery-seed/verify`, {
        method: 'POST',
        body: JSON.stringify({ seed: candidateSeed.trim() }),
      });
      setVerifyResult(res.valid ? "VALID" : "INVALID");
    } catch (err) {
      setError("Verification Error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleRecoverVault = async (e) => {
    e.preventDefault();
    if (!selectedVaultId || !recoverySeed.trim() || !newPassword.trim()) {
      alert("Please provide both recovery seed and new password.");
      return;
    }

    setLoading(true);
    setError("");
    setRecoverySuccess("");
    try {
      await CipherixAPI.request(`/vaults/${selectedVaultId}/recover`, {
        method: 'POST',
        body: JSON.stringify({
          recovery_seed: recoverySeed.trim(),
          new_password: newPassword.trim(),
        }),
      });
      setRecoverySuccess("Vault successfully recovered! Password updated and Master Key re-wrapped.");
      setRecoverySeed("");
      setNewPassword("");
    } catch (err) {
      setError("Vault Recovery Error: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#070a10]">
        <TopNavBar title="BIP-39 Vault Recovery" user={user} onLogout={onLogout} />

        <main className="max-w-4xl mx-auto p-6 space-y-6">
          <div className="glass-panel p-6 space-y-6 border-purple-500/20">
            <div className="flex flex-wrap justify-between items-center gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-xl font-bold font-outfit text-slate-100 flex items-center gap-2">
                  <LifeBuoy className="w-5 h-5 text-purple-400" />
                  <span>BIP-39 Vault Recovery Workflow</span>
                </h2>
                <p className="text-xs text-slate-400">16-word mnemonic seeds allow emergency recovery of locked vaults even if passwords are lost.</p>
              </div>
              <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
            </div>

            {error && <ErrorState message={error} />}
            {recoverySuccess && <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/40 text-emerald-300 text-xs font-semibold">{recoverySuccess}</div>}

            {/* Section 1: Generate Seed */}
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
              <div className="flex justify-between items-center">
                <div>
                  <h3 className="text-sm font-bold text-slate-100">1. Generate Recovery Seed</h3>
                  <p className="text-xs text-slate-400">Generates a BIP-39 mnemonic seed. Displayed ONCE — store offline safely.</p>
                </div>
                <button
                  onClick={handleGenerateSeed}
                  disabled={loading}
                  className="px-4 py-2 rounded-xl bg-purple-500 text-black font-bold text-xs flex items-center gap-1.5 hover:bg-purple-400 transition-colors"
                >
                  <Sparkles className="w-4 h-4" />
                  <span>Generate Seed</span>
                </button>
              </div>

              {generatedSeed && (
                <div className="p-4 rounded-xl bg-black border border-slate-800 space-y-2 text-xs">
                  <div className="flex justify-between items-center text-slate-400">
                    <span className="font-mono text-[10px] text-purple-400 uppercase font-bold">16-Word Recovery Mnemonic</span>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(generatedSeed);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className="hover:text-slate-100 flex items-center gap-1"
                    >
                      {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                      <span>{copied ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                  <div className="font-mono text-cyan-400 p-3 bg-slate-950 rounded-lg border border-slate-900 leading-relaxed select-all">
                    {generatedSeed}
                  </div>
                </div>
              )}
            </div>

            {/* Section 2: Recover Vault */}
            <div className="p-5 rounded-xl bg-slate-900/60 border border-slate-800 space-y-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100">2. Emergency Vault Recovery Flow</h3>
                <p className="text-xs text-slate-400">Enter your 16-word BIP-39 recovery seed to unlock a locked vault and rewrap it with a new password.</p>
              </div>

              <form onSubmit={handleRecoverVault} className="space-y-4">
                <div>
                  <label className="block text-xs font-bold uppercase text-slate-400 mb-1">16-Word BIP-39 Recovery Seed</label>
                  <textarea
                    value={recoverySeed}
                    onChange={(e) => setRecoverySeed(e.target.value)}
                    placeholder="e.g. alpha bravo cipher delta echo foxtrot golf hotel..."
                    className="w-full h-20 bg-slate-900 border border-slate-800 rounded-xl p-3 text-xs font-mono text-cyan-300 focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-slate-400 mb-1">New Vault Password</label>
                  <input
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    placeholder="Enter new vault password..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-purple-500"
                  />
                </div>

                <div className="flex justify-end">
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-5 py-2.5 rounded-xl bg-cyan-500 text-black font-bold text-xs flex items-center gap-2 hover:bg-cyan-400 transition-colors"
                  >
                    <KeyRound className="w-4 h-4" />
                    <span>Recover Vault & Reset Password</span>
                  </button>
                </div>
              </form>
            </div>
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
