import React, { useState, useEffect, useRef } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Brain, ShieldCheck, Send, Bot, User, Trash2, AlertTriangle, Sparkles } from 'lucide-react';

export function AIAssistantView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [prompt, setPrompt] = useState('');
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: 'Hello! I am your Cipherix AI Security Assistant. Select a vault and ask any question — I will retrieve relevant encrypted document chunks and generate grounded answers using local Ollama LLM.',
      sources: [],
      model: 'llama3.2:1b',
    },
  ]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const messagesEndRef = useRef(null);

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

  
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages, loading]);

  const handleSend = async (e) => {
    if (e) e.preventDefault();
    if (!prompt.trim() || !selectedVaultId) return;

    const userText = prompt.trim();
    setMessages((prev) => [...prev, { role: 'user', text: userText }]);
    setPrompt('');
    setLoading(true);
    setError('');

    try {
      const res = await CipherixAPI.request('/rag/query', {
        method: 'POST',
        body: JSON.stringify({
          vault_id: selectedVaultId,
          query: userText,
          top_k: 5,
          similarity_threshold: 0.3,
        }),
      });
      setMessages((prev) => [
        ...prev,
        {
          role: 'assistant',
          text: res.answer || 'No grounded answer generated.',
          sources: res.sources || [],
          model: res.llm_model || 'llama3.2:1b',
        },
      ]);
    } catch (err) {
      if (
        err.message.includes('503') ||
        err.message.toLowerCase().includes('unavailable') ||
        err.message.toLowerCase().includes('ollama')
      ) {
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            text: 'Ollama LLM Engine is currently unavailable offline. Grounded document search completed successfully, but local LLM generation requires Ollama running with llama3.2:1b.',
            sources: [],
            isWarning: true,
          },
        ]);
      } else {
        setError('RAG Query Error: ' + err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <PageLayout title="AI Security Assistant (Local RAG)" user={user} onLogout={onLogout} flexContent>

      {}
      <PageHeader
        icon={Brain}
        iconColor="text-emerald-400"
        title="AI Security Assistant"
        description="Local RAG · Vault-isolated · Zero external data leak"
      >
        <span className="badge-tag badge-emerald" style={{ whiteSpace: 'nowrap' }}>
          <ShieldCheck style={{ width: 12, height: 12 }} />
          <span>Injection Shield</span>
        </span>
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} label="" />
        <button
          onClick={() => setMessages([])}
          className="btn btn-ghost"
          style={{ padding: '7px 10px' }}
          title="Clear chat history"
        >
          <Trash2 style={{ width: 14, height: 14 }} />
          <span style={{ fontSize: '0.78rem' }}>Clear</span>
        </button>
      </PageHeader>

      {error && <ErrorState message={error} />}

      {}
      <div
        className="glass-panel"
        style={{
          flex: '1 1 0',
          minHeight: '420px',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
          borderColor: 'rgba(16,185,129,0.15)',
        }}
      >
        {}
        <div
          style={{
            padding: '10px 20px',
            borderBottom: '1px solid rgba(255,255,255,0.06)',
            background: 'rgba(0,0,0,0.25)',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            flexShrink: 0,
            gap: '8px',
          }}
        >
          <span style={{ fontSize: '0.78125rem', color: 'var(--text-muted)' }}>
            Answers grounded strictly in selected vault documents. Model:{' '}
            <strong style={{ color: 'var(--text-secondary)', fontFamily: "'JetBrains Mono', monospace" }}>
              llama3.2:1b
            </strong>
          </span>
          <span
            style={{
              fontSize: '0.6875rem',
              fontWeight: 700,
              color: 'var(--accent-emerald)',
              fontFamily: "'JetBrains Mono', monospace",
              whiteSpace: 'nowrap',
            }}
          >
            VAULT ISOLATED
          </span>
        </div>

        {}
        <div
          style={{
            flex: 1,
            overflowY: 'auto',
            padding: '20px',
            display: 'flex',
            flexDirection: 'column',
            gap: '16px',
          }}
        >
          {messages.map((m, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                gap: '12px',
                maxWidth: '88%',
                ...(m.role === 'user' ? { marginLeft: 'auto', flexDirection: 'row-reverse' } : {}),
              }}
            >
              {}
              <div
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: '50%',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                  border: '1px solid',
                  ...(m.role === 'user'
                    ? { background: 'rgba(34,211,238,0.15)', borderColor: 'rgba(34,211,238,0.35)', color: 'var(--accent-cyan)' }
                    : m.isWarning
                    ? { background: 'rgba(245,158,11,0.15)', borderColor: 'rgba(245,158,11,0.35)', color: 'var(--accent-amber)' }
                    : { background: 'rgba(16,185,129,0.15)', borderColor: 'rgba(16,185,129,0.35)', color: 'var(--accent-emerald)' }
                  ),
                }}
              >
                {m.role === 'user' ? (
                  <User style={{ width: 15, height: 15 }} />
                ) : m.isWarning ? (
                  <AlertTriangle style={{ width: 15, height: 15 }} />
                ) : (
                  <Bot style={{ width: 15, height: 15 }} />
                )}
              </div>

              {}
              <div
                style={{
                  padding: '14px 16px',
                  borderRadius: '16px',
                  border: '1px solid',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  ...(m.role === 'user'
                    ? {
                        background: 'linear-gradient(135deg, rgba(34,211,238,0.10), rgba(168,85,247,0.10))',
                        borderColor: 'rgba(34,211,238,0.25)',
                        color: 'var(--text-primary)',
                        borderTopRightRadius: '4px',
                      }
                    : m.isWarning
                    ? {
                        background: 'rgba(245,158,11,0.06)',
                        borderColor: 'rgba(245,158,11,0.25)',
                        color: '#fcd34d',
                        borderTopLeftRadius: '4px',
                      }
                    : {
                        background: 'rgba(7,10,18,0.70)',
                        borderColor: 'rgba(255,255,255,0.07)',
                        color: 'var(--text-primary)',
                        borderTopLeftRadius: '4px',
                      }
                  ),
                }}
              >
                {m.model && (
                  <div
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize: '0.6875rem',
                      color: 'var(--text-muted)',
                    }}
                  >
                    Engine: {m.model}
                  </div>
                )}
                <p style={{ fontSize: '0.875rem', lineHeight: 1.7, margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                  {m.text}
                </p>

                {m.sources && m.sources.length > 0 && (
                  <div
                    style={{
                      paddingTop: '10px',
                      borderTop: '1px solid rgba(255,255,255,0.08)',
                      display: 'flex',
                      flexWrap: 'wrap',
                      gap: '6px',
                      alignItems: 'center',
                    }}
                  >
                    <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600 }}>Sources:</span>
                    {m.sources.map((s, idx) => (
                      <span
                        key={idx}
                        className="badge-tag badge-purple"
                        style={{ fontSize: '0.6875rem' }}
                        title={`Chunk #${s.chunk_index}`}
                      >
                        <Sparkles style={{ width: 9, height: 9 }} />
                        {s.filename} ({(s.similarity * 100).toFixed(0)}%)
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}

          {}
          {loading && (
            <div style={{ display: 'flex', gap: '12px', maxWidth: '85%' }}>
              <div
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: '50%',
                  background: 'rgba(16,185,129,0.15)',
                  border: '1px solid rgba(16,185,129,0.35)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  flexShrink: 0,
                }}
              >
                <Bot style={{ width: 15, height: 15, color: 'var(--accent-emerald)' }} />
              </div>
              <div
                style={{
                  padding: '14px 16px',
                  borderRadius: '16px',
                  borderTopLeftRadius: '4px',
                  background: 'rgba(7,10,18,0.70)',
                  border: '1px solid rgba(255,255,255,0.07)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px',
                  color: 'var(--accent-emerald)',
                  fontSize: '0.8125rem',
                }}
              >
                <Brain style={{ width: 15, height: 15, animation: 'spin 2s linear infinite' }} />
                <span>Retrieving vault context &amp; generating answer...</span>
              </div>
            </div>
          )}

          <div ref={messagesEndRef} />
        </div>

        {}
        <form
          onSubmit={handleSend}
          style={{
            padding: '14px 16px',
            borderTop: '1px solid rgba(255,255,255,0.07)',
            background: 'rgba(4,6,12,0.60)',
            display: 'flex',
            gap: '10px',
            flexShrink: 0,
            alignItems: 'flex-end',
          }}
        >
          <textarea
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Ask a question about your encrypted vault documents… (Enter to send, Shift+Enter for newline)"
            rows={1}
            style={{
              flex: 1,
              background: 'var(--bg-input)',
              border: '1px solid rgba(255,255,255,0.10)',
              borderRadius: '12px',
              padding: '11px 14px',
              fontSize: '0.875rem',
              color: 'var(--text-primary)',
              outline: 'none',
              resize: 'none',
              fontFamily: 'inherit',
              lineHeight: 1.5,
              transition: 'border-color 160ms ease, box-shadow 160ms ease',
              maxHeight: '120px',
              overflow: 'auto',
            }}
            onFocus={e => {
              e.target.style.borderColor = 'rgba(16,185,129,0.40)';
              e.target.style.boxShadow = '0 0 0 3px rgba(16,185,129,0.07)';
            }}
            onBlur={e => {
              e.target.style.borderColor = 'rgba(255,255,255,0.10)';
              e.target.style.boxShadow = 'none';
            }}
          />
          <button
            type="submit"
            disabled={loading || !selectedVaultId}
            className="btn"
            style={{
              background: 'var(--accent-emerald)',
              color: '#050a12',
              padding: '11px 18px',
              borderRadius: '12px',
              gap: '7px',
              flexShrink: 0,
              alignSelf: 'flex-end',
              boxShadow: '0 4px 14px rgba(16,185,129,0.22)',
              transition: 'all 160ms',
              opacity: (loading || !selectedVaultId) ? 0.6 : 1,
            }}
            onMouseEnter={e => { if (!loading) { e.currentTarget.style.background = '#34d399'; e.currentTarget.style.transform = 'translateY(-1px)'; } }}
            onMouseLeave={e => { e.currentTarget.style.background = 'var(--accent-emerald)'; e.currentTarget.style.transform = 'translateY(0)'; }}
          >
            <Send style={{ width: 15, height: 15 }} />
            <span>Ask</span>
          </button>
        </form>
      </div>
    </PageLayout>
  );
}
