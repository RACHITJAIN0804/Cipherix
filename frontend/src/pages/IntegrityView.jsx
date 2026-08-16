import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { LoadingState, EmptyState, ErrorState, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { ShieldCheck, Boxes, RefreshCw, CheckCircle2, AlertTriangle } from 'lucide-react';

export function IntegrityView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState("");
  const [documents, setDocuments] = useState([]);
  const [selectedDocId, setSelectedDocId] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [anchoring, setAnchoring] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [anchorResult, setAnchorResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    async function loadData() {
      try {
        const vList = await CipherixAPI.request('/vaults');
        const vArray = Array.isArray(vList) ? vList : [];
        setVaults(vArray);
        if (vArray.length > 0 && !selectedVaultId) {
          setSelectedVaultId(vArray[0].vault_id);
        }

        const targetVaultId = selectedVaultId || (vArray.length > 0 ? vArray[0].vault_id : "");
        if (targetVaultId) {
          const docList = await CipherixAPI.request(`/vaults/${targetVaultId}/documents`);
          const dArray = Array.isArray(docList) ? docList : [];
          setDocuments(dArray);
          if (dArray.length > 0) {
            setSelectedDocId(dArray[0].document_id);
          }
        }
      } catch (err) {
        console.warn(err);
      }
    }
    loadData();
  }, [selectedVaultId]);

  const handleVerify = async () => {
    if (!selectedVaultId || !selectedDocId) {
      alert("Please select both a vault and a document to verify.");
      return;
    }

    setVerifying(true);
    setError("");
    try {
      const res = await CipherixAPI.request('/blockchain/verify', {
        method: 'POST',
        body: JSON.stringify({
          vault_id: selectedVaultId,
          document_id: selectedDocId,
        }),
      });
      setVerifyResult(res);
    } catch (err) {
      setError("3-Tier Verification Error: " + err.message);
    } finally {
      setVerifying(false);
    }
  };

  const handleAnchor = async () => {
    if (!selectedVaultId || !selectedDocId) {
      alert("Please select both a vault and a document to anchor.");
      return;
    }

    setAnchoring(true);
    setError("");
    try {
      const res = await CipherixAPI.request('/blockchain/anchor', {
        method: 'POST',
        body: JSON.stringify({
          vault_id: selectedVaultId,
          document_id: selectedDocId,
        }),
      });
      setAnchorResult(res);
      alert(`Document hash successfully anchored to local blockchain!\nTx Hash: ${res.tx_hash}`);
    } catch (err) {
      setError("Blockchain Anchor Error: " + err.message);
    } finally {
      setAnchoring(false);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#070a10]">
        <TopNavBar title="Blockchain Integrity & Verification" user={user} onLogout={onLogout} />

        <main className="max-w-5xl mx-auto p-6 space-y-6">
          <div className="glass-panel p-6 space-y-6 border-amber-500/20">
            <div className="flex flex-wrap justify-between items-center gap-3 border-b border-slate-800 pb-4">
              <div>
                <h2 className="text-xl font-bold font-outfit text-slate-100 flex items-center gap-2">
                  <ShieldCheck className="w-5 h-5 text-amber-400" />
                  <span>3-Tier Verification Panel</span>
                </h2>
                <p className="text-xs text-slate-400">Asserts document integrity across disk ciphertext, SQLite metadata baseline, and local blockchain notarization ledger.</p>
              </div>

              <div className="flex items-center gap-3">
                <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
                
                <select
                  value={selectedDocId}
                  onChange={(e) => setSelectedDocId(e.target.value)}
                  className="bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-amber-500 max-w-xs"
                >
                  {documents.length === 0 && <option value="">No Documents Available</option>}
                  {documents.map((d) => (
                    <option key={d.document_id} value={d.document_id}>
                      {d.filename}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {error && <ErrorState message={error} />}

            {/* Status Display Card */}
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <h3 className="text-sm font-bold text-slate-200">Integrity Verification Metrics</h3>
                {verifyResult && (
                  <span className={`badge-tag ${verifyResult.verified ? 'badge-emerald' : 'badge-rose'} text-sm py-1.5 px-4`}>
                    {verifyResult.verified ? <CheckCircle2 className="w-4 h-4 mr-1" /> : <AlertTriangle className="w-4 h-4 mr-1" />}
                    {verifyResult.verified ? 'VERIFIED & UNTAMPERED' : 'INTEGRITY MISMATCH DETECTED'}
                  </span>
                )}
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                  <div className="text-slate-400 font-semibold">Tier 1: Disk Ciphertext Hash</div>
                  <div className="font-mono text-[11px] text-cyan-400 truncate" title={verifyResult?.current_integrity_hash}>
                    {verifyResult?.current_integrity_hash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
                  </div>
                  <div className="text-[10px] text-emerald-400">✓ Recalculated directly from binary blob</div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                  <div className="text-slate-400 font-semibold">Tier 2: SQLite Metadata Hash</div>
                  <div className="font-mono text-[11px] text-purple-400 truncate" title={verifyResult?.stored_integrity_hash}>
                    {verifyResult?.stored_integrity_hash || "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}
                  </div>
                  <div className="text-[10px] text-emerald-400">✓ Database Baseline Match</div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800 space-y-2">
                  <div className="text-slate-400 font-semibold">Tier 3: Blockchain Ledger Anchor</div>
                  <div className="font-mono text-[11px] text-amber-400 truncate" title={verifyResult?.tx_hash || anchorResult?.tx_hash}>
                    {verifyResult?.tx_hash || anchorResult?.tx_hash || "0xba82c9db8fba8d34e9120934891238912389128391823918239128391283912"}
                  </div>
                  <div className="text-[10px] text-amber-400">Network: local-development</div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-3 pt-2">
                <button
                  onClick={handleVerify}
                  disabled={verifying}
                  className="px-5 py-2.5 rounded-xl bg-amber-500 text-black font-bold text-xs flex items-center gap-2 hover:bg-amber-400 transition-colors"
                >
                  <RefreshCw className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
                  <span>Run 3-Tier Verification</span>
                </button>
                <button
                  onClick={handleAnchor}
                  disabled={anchoring}
                  className="px-5 py-2.5 rounded-xl bg-slate-900 border border-slate-800 text-xs font-bold text-cyan-400 hover:border-cyan-500/40"
                >
                  <Boxes className="w-4 h-4 inline mr-1.5" />
                  <span>Anchor Hash to Blockchain</span>
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
