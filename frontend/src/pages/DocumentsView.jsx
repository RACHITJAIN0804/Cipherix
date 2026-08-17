import React, { useState, useEffect } from 'react';
import { TopNavBar } from '../components/TopNavBar';
import { PageTransition } from '../components/PageTransition';
import { LoadingState, EmptyState, ErrorState, ConfirmDialog, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { FileText, Download, Boxes, Check, Upload, Trash2, Play, RefreshCw, X } from 'lucide-react';

export function DocumentsView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState("");
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Modals & Actions state
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [vaultPassword, setVaultPassword] = useState("");
  const [uploadFile, setUploadFile] = useState(null);
  const [deleteDocId, setDeleteDocId] = useState(null);
  const [processingDocId, setProcessingDocId] = useState(null);
  const [statusMsg, setStatusMsg] = useState("");

  const fetchVaultsAndDocs = async () => {
    setLoading(true);
    setError("");
    try {
      const vaultList = await CipherixAPI.request('/vaults');
      const vArray = Array.isArray(vaultList) ? vaultList : [];
      setVaults(vArray);
      
      const targetVaultId = selectedVaultId || (vArray.length > 0 ? vArray[0].vault_id : "");
      if (!selectedVaultId && targetVaultId) {
        setSelectedVaultId(targetVaultId);
      }

      if (targetVaultId) {
        const docList = await CipherixAPI.request(`/vaults/${targetVaultId}/documents`);
        setDocuments(Array.isArray(docList) ? docList : []);
      }
    } catch (err) {
      setError("Failed to load documents: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchVaultsAndDocs();
  }, [selectedVaultId]);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!uploadFile || !vaultPassword || !selectedVaultId) {
      alert("Please select a file and enter the vault password.");
      return;
    }

    const formData = new FormData();
    formData.append("file", uploadFile);

    try {
      setStatusMsg("Encrypting & Uploading...");
      await CipherixAPI.request(`/vaults/${selectedVaultId}/documents`, {
        method: 'POST',
        headers: { "X-Vault-Password": vaultPassword },
        body: formData,
      });
      setUploadModalOpen(false);
      setUploadFile(null);
      setStatusMsg("");
      fetchVaultsAndDocs();
    } catch (err) {
      alert("Upload Error: " + err.message);
      setStatusMsg("");
    }
  };

  const handleProcessDocument = async (docId) => {
    const pwd = prompt("Enter Vault Password to decrypt and process text chunks:");
    if (!pwd) return;

    setProcessingDocId(docId);
    try {
      const res = await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${docId}/process`, {
        method: 'POST',
        headers: { "X-Vault-Password": pwd },
      });
      alert(`Document processed into ${res.chunk_count || 1} vector chunks ready for RAG!`);
      fetchVaultsAndDocs();
    } catch (err) {
      alert("Processing Error: " + err.message);
    } finally {
      setProcessingDocId(null);
    }
  };

  const handleDownloadDocument = async (docId, filename) => {
    const pwd = prompt("Enter Vault Password to stream-decrypt document:");
    if (!pwd) return;

    try {
      const blob = await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${docId}`, {
        method: 'GET',
        headers: { "X-Vault-Password": pwd },
        responseType: 'blob'
      });
      if (blob instanceof Blob) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.click();
      } else {
        alert("Decrypted stream download initiated!");
      }
    } catch (err) {
      alert("Download Decryption Error: " + err.message);
    }
  };

  const handleDeleteDocument = async () => {
    if (!deleteDocId || !selectedVaultId) return;
    try {
      await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${deleteDocId}`, {
        method: 'DELETE',
      });
      setDeleteDocId(null);
      fetchVaultsAndDocs();
    } catch (err) {
      alert("Delete Error: " + err.message);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12]">
        <TopNavBar title="Encrypted Document Storage" user={user} onLogout={onLogout} />

        <main className="max-w-[1400px] mx-auto p-6 space-y-6">
          <div className="flex flex-wrap justify-between items-center gap-4">
            <div>
              <h2 className="text-xl font-bold font-outfit text-slate-100">Encrypted Document Storage</h2>
              <p className="text-xs text-slate-400">Documents are AES-256-GCM encrypted before storage. SHA-256 integrity hashes baseline state.</p>
            </div>
            
            <div className="flex items-center gap-3">
              <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
              <button
                onClick={() => setUploadModalOpen(true)}
                className="px-4 py-2.5 rounded-xl bg-gradient-to-r from-purple-500 to-cyan-500 text-black font-bold text-xs flex items-center gap-2 hover:opacity-90 transition-opacity"
              >
                <Upload className="w-4 h-4" />
                <span>Upload Document</span>
              </button>
            </div>
          </div>

          {error && <ErrorState message={error} onRetry={fetchVaultsAndDocs} />}

          {loading ? (
            <LoadingState message="Loading encrypted documents..." />
          ) : documents.length === 0 ? (
            <EmptyState title="No Documents In Vault" description="Upload a TXT, PDF, or DOCX document to store it securely." actionLabel="Upload File" onAction={() => setUploadModalOpen(true)} />
          ) : (
            <div className="glass-panel overflow-hidden p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-left border-collapse text-xs">
                  <thead>
                    <tr className="bg-slate-900/80 text-slate-400 uppercase font-bold text-[11px] border-b border-slate-800">
                      <th className="p-4">Filename</th>
                      <th className="p-4">MIME / Size</th>
                      <th className="p-4">SHA-256 Integrity Hash</th>
                      <th className="p-4">RAG Status</th>
                      <th className="p-4 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {documents.map((d) => (
                      <tr key={d.document_id} className="hover:bg-slate-900/40 transition-colors">
                        <td className="p-4 font-semibold text-slate-100 flex items-center gap-2">
                          <FileText className="w-4 h-4 text-purple-400 shrink-0" />
                          <span className="truncate max-w-[200px]">{d.filename}</span>
                        </td>
                        <td className="p-4 text-slate-400">
                          <div>{d.mime_type}</div>
                          <div className="text-[10px]">{(d.file_size_bytes / 1024).toFixed(1)} KB</div>
                        </td>
                        <td className="p-4">
                          <div className="font-mono text-[11px] text-cyan-400 truncate max-w-[220px]" title={d.integrity_hash}>
                            {d.integrity_hash}
                          </div>
                        </td>
                        <td className="p-4">
                          <span className={`badge-tag ${d.processing_status === 'processed' ? 'badge-emerald' : 'badge-amber'}`}>
                            {d.processing_status === 'processed' ? <Check className="w-3 h-3" /> : <RefreshCw className="w-3 h-3 animate-spin" />}
                            <span>{d.processing_status || 'uploaded'}</span>
                          </span>
                        </td>
                        <td className="p-4 text-right space-x-1.5">
                          <button
                            onClick={() => handleProcessDocument(d.document_id)}
                            disabled={processingDocId === d.document_id}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-purple-300 hover:border-purple-500/40"
                            title="Extract & Chunk Text for RAG"
                          >
                            <Play className="w-3.5 h-3.5 inline mr-1" /> Process
                          </button>
                          <button
                            onClick={() => handleDownloadDocument(d.document_id, d.filename)}
                            className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-200 hover:text-cyan-400"
                            title="Decrypt & Stream Download"
                          >
                            <Download className="w-3.5 h-3.5 inline mr-1" /> Decrypt
                          </button>
                          <button
                            onClick={() => setDeleteDocId(d.document_id)}
                            className="p-1.5 rounded-lg bg-slate-900 border border-slate-800 text-slate-500 hover:text-rose-400"
                            title="Delete Document"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </main>

        {/* Upload Modal */}
        {uploadModalOpen && (
          <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
            <div className="glass-panel max-w-md w-full p-6 space-y-4 relative border-slate-800">
              <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                <h3 className="text-lg font-bold font-outfit text-slate-100">Upload Encrypted Document</h3>
                <button onClick={() => setUploadModalOpen(false)} className="text-slate-400 hover:text-slate-100">
                  <X className="w-5 h-5" />
                </button>
              </div>

              <form onSubmit={handleUpload} className="space-y-4">
                {/* Drag and Drop Zone */}
                <div
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={(e) => {
                    e.preventDefault();
                    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                      setUploadFile(e.dataTransfer.files[0]);
                    }
                  }}
                  className="border-2 border-dashed border-slate-700 hover:border-cyan-500 rounded-2xl p-6 text-center space-y-2 cursor-pointer transition-colors bg-slate-900/40"
                >
                  <Upload className="w-8 h-8 mx-auto text-cyan-400" />
                  <div className="text-xs text-slate-200 font-medium">
                    {uploadFile ? uploadFile.name : "Drag & drop TXT, PDF, or DOCX file here"}
                  </div>
                  <input
                    type="file"
                    onChange={(e) => e.target.files && setUploadFile(e.target.files[0])}
                    className="hidden"
                    id="file-input"
                  />
                  <label htmlFor="file-input" className="inline-block px-3 py-1 rounded-lg bg-slate-800 text-[11px] text-cyan-400 font-semibold cursor-pointer">
                    Browse Files
                  </label>
                </div>

                <div>
                  <label className="block text-xs font-bold uppercase text-slate-400 mb-1">Vault Unlock Password</label>
                  <input
                    type="password"
                    value={vaultPassword}
                    onChange={(e) => setVaultPassword(e.target.value)}
                    placeholder="Password required to derive Master Key..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl px-3 py-2 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>

                {statusMsg && <div className="text-xs text-cyan-400 animate-pulse font-medium text-center">{statusMsg}</div>}

                <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                  <button type="button" onClick={() => setUploadModalOpen(false)} className="px-4 py-2 rounded-xl bg-slate-900 text-xs font-semibold text-slate-300">
                    Cancel
                  </button>
                  <button type="submit" className="px-4 py-2 rounded-xl bg-cyan-500 text-black text-xs font-bold">
                    Encrypt & Upload
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Delete Confirmation */}
        <ConfirmDialog
          isOpen={!!deleteDocId}
          title="Delete Encrypted Document"
          message="Are you sure you want to permanently delete this document binary blob and its SHA-256 integrity metadata?"
          confirmLabel="Delete Document"
          onConfirm={handleDeleteDocument}
          onCancel={() => setDeleteDocId(null)}
        />
      </div>
    </PageTransition>
  );
}
