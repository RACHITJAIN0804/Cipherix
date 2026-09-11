import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Search, FileText, Send, Sparkles, SlidersHorizontal } from 'lucide-react';

export function AISearchView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [query, setQuery] = useState('');
  const [topK, setTopK] = useState(5);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [hasSearched, setHasSearched] = useState(false);

  useEffect(() => {
    async function loadVaults() {
      try {
        const data = await CipherixAPI.request('/vaults');
        const vList = Array.isArray(data) ? data : [];
        setVaults(vList);
        if (vList.length > 0 && !selectedVaultId) setSelectedVaultId(vList[0].vault_id);
      } catch (err) { console.warn(err); }
    }
    loadVaults();
  }, []);

  const handleSearch = async (e) => {
    if (e) e.preventDefault();
    if (!query.trim() || !selectedVaultId) return;

    setLoading(true);
    setError('');
    setHasSearched(true);
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
      <div
        className="glass-panel"
        style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}
      >
        <form onSubmit={handleSearch} style={{ display: 'flex', gap: '10px' }}>
          <div style={{ position: 'relative', flex: 1 }}>
            <Search
              style={{
                position: 'absolute',
                left: '14px',
                top: '50%',
                transform: 'translateY(-50%)',
                width: 15,
                height: 15,
                color: 'var(--text-muted)',
                pointerEvents: 'none',
              }}
            />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Enter natural language query..."
              style={{
                width: '100%',
                background: 'var(--bg-input)',
                border: '1px solid rgba(255,255,255,0.10)',
                borderRadius: '12px',
                padding: '11px 14px 11px 40px',
                fontSize: '0.875rem',
                color: 'var(--text-primary)',
                outline: 'none',
                transition: 'border-color 160ms ease, box-shadow 160ms ease',
                boxSizing: 'border-box',
                fontFamily: 'inherit',
              }}
              onFocus={e => {
                e.target.style.borderColor = 'rgba(59,130,246,0.45)';
                e.target.style.boxShadow = '0 0 0 3px rgba(59,130,246,0.08)';
              }}
              onBlur={e => {
                e.target.style.borderColor = 'rgba(255,255,255,0.10)';
                e.target.style.boxShadow = 'none';
              }}
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="btn"
            style={{
              background: 'var(--accent-blue)',
              color: '#050a12',
              padding: '11px 20px',
              borderRadius: '12px',
              fontSize: '0.875rem',
              gap: '7px',
              flexShrink: 0,
              boxShadow: '0 4px 14px rgba(59,130,246,0.25)',
              transition: 'all 160ms',
            }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = '#60a5fa'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-blue)'; e.currentTarget.style.transform = 'translateY(0)'; }}
          >
            <Send style={{ width: 15, height: 15 }} />
            <span>{loading ? 'Searching...' : 'Search'}</span>
          </button>
        </form>

        {/* Top-K slider */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            paddingTop: '14px',
            borderTop: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <SlidersHorizontal style={{ width: 13, height: 13, color: 'var(--text-muted)', flexShrink: 0 }} />
          <label style={{ fontSize: '0.78125rem', color: 'var(--text-secondary)', fontWeight: 600, whiteSpace: 'nowrap' }}>
            Top K Results:
          </label>
          <input
            type="range"
            min="1" max="10" step="1"
            value={topK}
            onChange={(e) => setTopK(e.target.value)}
            style={{ width: '120px', accentColor: '#A855F7', cursor: 'pointer' }}
          />
          <span
            style={{
              fontSize: '0.875rem',
              fontWeight: 700,
              color: 'var(--accent-purple)',
              minWidth: '16px',
              textAlign: 'center',
            }}
          >
            {topK}
          </span>
        </div>
      </div>

      {error && <ErrorState message={error} onRetry={handleSearch} />}

      {/* Results Section */}
      <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
        {/* Section header */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            paddingBottom: '14px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
          }}
        >
          <h3
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '8px',
              fontSize: '0.875rem',
              fontWeight: 700,
              color: 'var(--text-secondary)',
              margin: 0,
              letterSpacing: '0.04em',
              textTransform: 'uppercase',
              fontFamily: 'inherit',
            }}
          >
            <Sparkles style={{ width: 14, height: 14, color: 'var(--accent-purple)' }} />
            Matching Text Chunks
          </h3>
          {results.length > 0 && (
            <span className="badge-tag badge-purple">{results.length} results</span>
          )}
        </div>

        {loading ? (
          <LoadingState message="Generating query embeddings & searching ChromaDB..." />
        ) : !hasSearched ? (
          <EmptyState
            title="Ready to Search"
            description="Enter a natural language query above and hit Search to find semantic text matches in your vault."
          />
        ) : results.length === 0 ? (
          <EmptyState
            title="No Search Results"
            description="No matching chunks found for your query. Try different keywords or check that documents are processed."
          />
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {results.map((r, idx) => (
              <div
                key={r.chunk_id || idx}
                className="glass-panel"
                style={{
                  padding: '18px 20px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '12px',
                  borderColor: 'rgba(168,85,247,0.12)',
                }}
              >
                {/* Result header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
                    <FileText style={{ width: 15, height: 15, color: 'var(--accent-purple)', flexShrink: 0 }} />
                    <span style={{ fontSize: '0.875rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {r.filename || 'Document'}
                    </span>
                    {r.page_number && (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                        (Page {r.page_number})
                      </span>
                    )}
                  </div>
                  <span className="badge-tag badge-cyan" style={{ fontFamily: "'JetBrains Mono', monospace", flexShrink: 0 }}>
                    {(r.similarity_score * 100).toFixed(1)}% match
                  </span>
                </div>

                {/* Snippet */}
                <p
                  style={{
                    fontFamily: "'JetBrains Mono', 'Courier New', monospace",
                    fontSize: '0.8rem',
                    color: '#CBD5E1',
                    padding: '14px 16px',
                    background: 'rgba(0,0,0,0.35)',
                    borderRadius: '10px',
                    border: '1px solid rgba(255,255,255,0.06)',
                    lineHeight: 1.7,
                    margin: 0,
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-word',
                  }}
                >
                  "{r.text_snippet}"
                </p>

                {/* Metadata */}
                <div
                  style={{
                    display: 'flex',
                    gap: '16px',
                    fontSize: '0.6875rem',
                    color: 'var(--text-muted)',
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  <span>Chunk: {r.chunk_id || `chunk_${idx}`}</span>
                  <span>Doc: {r.document_id}</span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </PageLayout>
  );
}
