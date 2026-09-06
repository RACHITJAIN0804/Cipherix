import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Search, FileText, Send, Sparkles } from 'lucide-react';

export function AISearchView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [query, setQuery] = useState('');
  const [topK, setTopK] = useState(5);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

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

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    if (!query.trim() || !selectedVaultId) return;

    setLoading(true);
    setError('');
    try {
      const res = await CipherixAPI.request('/search', {
        method: 'POST',
        body: JSON.stringify({
          vault_id: selectedVaultId,
          query: query.trim(),
          top_k: parseInt(topK),
        }),
      });
      setResults(res.results || []);
    } catch (err) {
      setError('Search Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageLayout title="Vault-Isolated AI Search" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={Search}
        iconColor="text-blue-400"
        title="Vault-Isolated Semantic Vector Search"
        description="Search text embeddings belonging exclusively to the selected vault using SentenceTransformers."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
      </PageHeader>

      {/* Search Panel */}
      <div className="glass-panel p-6 flex flex-col gap-4 border-blue-500/20">
        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="w-4 h-4 absolute left-4 top-3.5 text-slate-500 pointer-events-none" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter natural language query (e.g. 'security protocol parameters')..."
              className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-11 pr-4 py-3 text-xs text-slate-100 focus:outline-none focus:border-blue-500 transition-colors"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-blue-500 text-black font-bold text-xs flex items-center gap-2 hover:bg-blue-400 transition-colors disabled:opacity-60"
          >
            <Send className="w-4 h-4" />
            <span>Search</span>
          </button>
        </form>

        <div className="flex items-center gap-4 text-xs pt-2 border-t border-slate-800/80">
          <label className="text-slate-400 font-semibold">Top K Results Matches:</label>
          <input
            type="range"
            min="1"
            max="10"
            step="1"
            value={topK}
            onChange={(e) => setTopK(e.target.value)}
            className="w-36 accent-purple-500"
          />
          <span className="font-bold text-purple-400">{topK}</span>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={handleSearch} />}

      {/* Results Section */}
      <div className="flex flex-col gap-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
          <Sparkles className="w-3.5 h-3.5 text-purple-400" />
          <span>Matching Text Chunks ({results.length})</span>
        </h3>

        {loading ? (
          <LoadingState message="Generating query embeddings & searching ChromaDB..." />
        ) : results.length === 0 ? (
          <EmptyState
            title="No Search Results"
            description="Enter a query above and hit Search to find semantic text matches."
          />
        ) : (
          results.map((r, idx) => (
            <div key={r.chunk_id || idx} className="glass-panel p-5 flex flex-col gap-3 border-purple-500/20 hover:border-cyan-500/40 transition-colors">
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-2 font-bold text-slate-100">
                  <FileText className="w-4 h-4 text-purple-400 flex-shrink-0" />
                  <span>{r.filename || 'Document'}</span>
                  {r.page_number && (
                    <span className="text-slate-400 font-normal text-[11px]">(Page {r.page_number})</span>
                  )}
                </div>
                <span className="badge-tag badge-cyan font-mono text-[11px] flex-shrink-0">
                  {(r.similarity_score * 100).toFixed(1)}% Similarity
                </span>
              </div>

              <p className="text-xs text-slate-200 font-mono p-4 bg-slate-900/90 rounded-xl border border-slate-800/80 leading-relaxed">
                &quot;{r.text_snippet}&quot;
              </p>

              <div className="text-[10px] text-slate-500 font-mono flex gap-3 pt-1">
                <span>Chunk ID: {r.chunk_id || `chunk_${idx}`}</span>
                <span>Document ID: {r.document_id}</span>
              </div>
            </div>
          ))
        )}
      </div>
    </PageLayout>
  );
}
