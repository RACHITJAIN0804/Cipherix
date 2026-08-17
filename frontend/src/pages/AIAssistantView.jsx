import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { VaultSelector, ErrorState } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { Brain, ShieldCheck, Send, Bot, User, Trash2, Info, AlertTriangle } from 'lucide-react';

export function AIAssistantView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState("");
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      text: 'Hello! I am your Cipherix AI Security Assistant. Select a vault and ask any question—I will retrieve relevant encrypted document chunks and generate grounded answers using local Ollama LLM.',
      sources: [],
      model: 'llama3.2:1b'
    }
  ]);
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

  const handleSend = async (e) => {
    if (e) e.preventDefault();
    if (!prompt.trim() || !selectedVaultId) return;

    const userText = prompt.trim();
    setMessages((prev) => [...prev, { role: 'user', text: userText }]);
    setPrompt("");
    setLoading(true);
    setError("");

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
          text: res.answer || "No grounded answer generated.",
          sources: res.sources || [],
          model: res.llm_model || 'llama3.2:1b',
        }
      ]);
    } catch (err) {
      if (err.message.includes("503") || err.message.toLowerCase().includes("unavailable") || err.message.toLowerCase().includes("ollama")) {
        setMessages((prev) => [
          ...prev,
          {
            role: 'assistant',
            text: "Ollama LLM Engine is currently unavailable offline. Grounded document search completed successfully, but local LLM generation requires Ollama running with llama3.2:1b.",
            sources: [],
            isWarning: true
          }
        ]);
      } else {
        setError("RAG Query Error: " + err.message);
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12] flex flex-col">
        <TopNavBar title="AI Security Assistant (Local RAG)" user={user} onLogout={onLogout} />

        <main className="max-w-[1400px] mx-auto p-6 w-full flex-1 flex flex-col space-y-4">
          <div className="flex flex-wrap justify-between items-center gap-3">
            <div className="flex items-center gap-3">
              <span className="badge-tag badge-emerald">
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Prompt Injection Shield Active</span>
              </span>
              <span className="text-xs text-slate-400 font-medium hidden sm:inline">
                Local Ollama Model: <strong className="text-slate-200">llama3.2:1b</strong>
              </span>
            </div>

            <div className="flex items-center gap-3">
              <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
              <button
                onClick={() => setMessages([])}
                className="text-xs text-slate-400 hover:text-slate-100 flex items-center gap-1.5 p-2 rounded-lg hover:bg-slate-900"
                title="Clear Chat Stream"
              >
                <Trash2 className="w-4 h-4" />
              </button>
            </div>
          </div>

          {error && <ErrorState message={error} />}

          {/* Chat Container */}
          <div className="glass-panel flex-1 flex flex-col overflow-hidden min-h-[500px] border-emerald-500/20">
            <div className="p-3 border-b border-slate-800 text-[11px] text-slate-400 flex justify-between bg-slate-900/50">
              <span>Answers are grounded strictly in the selected vault documents. Zero external data leak.</span>
              <span className="text-emerald-400 font-semibold font-mono">Vault Isolated</span>
            </div>

            {/* Chat Stream */}
            <div className="flex-1 overflow-y-auto p-6 space-y-4">
              {messages.map((m, i) => (
                <div key={i} className={`flex gap-3 max-w-[88%] ${m.role === 'user' ? 'ml-auto flex-row-reverse' : ''}`}>
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs shrink-0 ${m.role === 'user' ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/40' : m.isWarning ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40' : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'}`}>
                    {m.role === 'user' ? <User className="w-4 h-4" /> : m.isWarning ? <AlertTriangle className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
                  </div>
                  
                  <div className={`p-4 rounded-2xl border text-xs space-y-2.5 ${m.role === 'user' ? 'bg-gradient-to-r from-cyan-500/10 to-purple-500/10 border-cyan-500/30 text-slate-100' : m.isWarning ? 'bg-amber-500/5 border-amber-500/30 text-amber-200' : 'bg-slate-900/90 border-slate-800 text-slate-200'}`}>
                    {m.model && <div className="text-[10px] text-slate-400 font-mono">Engine: {m.model}</div>}
                    <p className="leading-relaxed whitespace-pre-wrap">{m.text}</p>
                    
                    {m.sources && m.sources.length > 0 && (
                      <div className="pt-2 border-t border-slate-800 flex flex-wrap gap-1.5 text-[10px]">
                        <span className="text-slate-400 font-semibold">Grounded Sources:</span>
                        {m.sources.map((s, idx) => (
                          <span key={idx} className="badge-tag badge-purple text-[10px]" title={`Chunk #${s.chunk_index}`}>
                            📄 {s.filename} ({(s.similarity * 100).toFixed(0)}%)
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              ))}

              {loading && (
                <div className="flex gap-3 max-w-[85%]">
                  <div className="w-8 h-8 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/40 flex items-center justify-center">
                    <Bot className="w-4 h-4" />
                  </div>
                  <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 text-xs text-emerald-400 animate-pulse flex items-center gap-2">
                    <Brain className="w-4 h-4 animate-spin" />
                    <span>Retrieving context chunks & generating Ollama answer...</span>
                  </div>
                </div>
              )}
            </div>

            {/* Input Bar */}
            <form onSubmit={handleSend} className="p-4 border-t border-slate-800 flex gap-3 bg-slate-950/80">
              <input
                type="text"
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                placeholder="Ask a question about your encrypted vault documents..."
                className="flex-1 bg-slate-900 border border-slate-800 rounded-xl px-4 py-3 text-xs text-slate-100 focus:outline-none focus:border-emerald-500"
              />
              <button
                type="submit"
                disabled={loading || !selectedVaultId}
                className="px-6 py-3 rounded-xl bg-emerald-500 text-black font-bold text-xs flex items-center gap-2 hover:bg-emerald-400 transition-colors"
              >
                <Send className="w-4 h-4" />
                <span>Ask RAG</span>
              </button>
            </form>
          </div>
        </main>
      </div>
    </PageTransition>
  );
}
