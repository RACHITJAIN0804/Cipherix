import React, { useState, useEffect } from 'react';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, ConfirmDialog, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { FileText, Download, Check, Upload, Trash2, Play, RefreshCw, X, CloudUpload } from 'lucide-react';

export function DocumentsView({ user, onLogout }) {
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState('');
  const [documents, setDocuments] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [vaultPassword, setVaultPassword] = useState('');
  const [uploadFile, setUploadFile] = useState(null);
  const [deleteDocId, setDeleteDocId] = useState(null);
  const [processingDocId, setProcessingDocId] = useState(null);
  const [statusMsg, setStatusMsg] = useState('');
  const [dragOver, setDragOver] = useState(false);

  const fetchVaultsAndDocs = async () => {
    setLoading(true);
    setError('');
    try {
      const vaultList = await CipherixAPI.request('/vaults');
      const vArray = Array.isArray(vaultList) ? vaultList : [];
      setVaults(vArray);

      const targetVaultId = selectedVaultId || (vArray.length > 0 ? vArray[0].vault_id : '');
      if (!selectedVaultId && targetVaultId) setSelectedVaultId(targetVaultId);

      if (targetVaultId) {
        const docList = await CipherixAPI.request(`/vaults/${targetVaultId}/documents`);
        setDocuments(Array.isArray(docList) ? docList : []);
      }
    } catch (err) {
      setError('Failed to load documents: ' + err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchVaultsAndDocs(); }, [selectedVaultId]);

  const handleUpload = async (e) => {
    e.preventDefault();
    if (!uploadFile || !vaultPassword || !selectedVaultId) {
      alert('Please select a file and enter the vault password.');
      return;
    }
    const formData = new FormData();
    formData.append('file', uploadFile);
    try {
      setStatusMsg('Encrypting & Uploading...');
      await CipherixAPI.request(`/vaults/${selectedVaultId}/documents`, {
        method: 'POST',
        headers: { 'X-Vault-Password': vaultPassword },
        body: formData,
      });
      setUploadModalOpen(false);
      setUploadFile(null);
      setVaultPassword('');
      setStatusMsg('');
      fetchVaultsAndDocs();
    } catch (err) {
      alert('Upload Error: ' + err.message);
      setStatusMsg('');
    }
  };

  const handleProcessDocument = async (docId) => {
    const pwd = prompt('Enter Vault Password to decrypt and process text chunks:');
    if (!pwd) return;
    setProcessingDocId(docId);
    try {
      const res = await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${docId}/process`, {
        method: 'POST',
        headers: { 'X-Vault-Password': pwd },
      });
      alert(`Document processed into ${res.chunk_count || 1} vector chunks ready for RAG!`);
      fetchVaultsAndDocs();
    } catch (err) {
      alert('Processing Error: ' + err.message);
    } finally {
      setProcessingDocId(null);
    }
  };

  const handleDownloadDocument = async (docId, filename) => {
    const pwd = prompt('Enter Vault Password to stream-decrypt document:');
    if (!pwd) return;
    try {
      const blob = await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${docId}`, {
        method: 'GET',
        headers: { 'X-Vault-Password': pwd },
        responseType: 'blob',
      });
      if (blob instanceof Blob) {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = filename; a.click();
      } else {
        alert('Decrypted stream download initiated!');
      }
    } catch (err) {
      alert('Download Decryption Error: ' + err.message);
    }
  };

  const handleDeleteDocument = async () => {
    if (!deleteDocId || !selectedVaultId) return;
    try {
      await CipherixAPI.request(`/vaults/${selectedVaultId}/documents/${deleteDocId}`, { method: 'DELETE' });
      setDeleteDocId(null);
      fetchVaultsAndDocs();
    } catch (err) {
      alert('Delete Error: ' + err.message);
    }
  };

  const inputStyle = {
    width: '100%',
    background: 'var(--bg-input)',
    border: '1px solid rgba(255,255,255,0.10)',
    borderRadius: '10px',
    padding: '10px 14px',
    fontSize: '0.8125rem',
    color: 'var(--text-primary)',
    outline: 'none',
    transition: 'border-color 160ms ease, box-shadow 160ms ease',
    boxSizing: 'border-box',
    fontFamily: 'inherit',
  };

  return (
    <PageLayout title="Encrypted Document Storage" user={user} onLogout={onLogout}>
      {/* Page Header */}
      <PageHeader
        icon={FileText}
        iconColor="text-purple-400"
        title="Encrypted Document Storage"
        description="Documents are AES-256-GCM encrypted before storage. SHA-256 integrity hashes baseline state."
      >
        <VaultSelector vaults={vaults} selectedVaultId={selectedVaultId} onChange={setSelectedVaultId} />
        <button
          onClick={() => setUploadModalOpen(true)}
          className="btn btn-primary"
          style={{ background: 'linear-gradient(135deg, #A855F7, #22D3EE)' }}
        >
          <Upload style={{ width: 14, height: 14 }} />
          <span>Upload Document</span>
        </button>
      </PageHeader>

      {error && <ErrorState message={error} onRetry={fetchVaultsAndDocs} />}

      {loading ? (
        <LoadingState message="Loading encrypted documents..." />
      ) : documents.length === 0 ? (
        <EmptyState
          title="No Documents In Vault"
          description="Upload a TXT, PDF, or DOCX document to store it securely with AES-256-GCM encryption."
          actionLabel="Upload File"
          onAction={() => setUploadModalOpen(true)}
        />
      ) : (
        <div
          className="glass-panel"
          style={{ padding: 0, overflow: 'hidden' }}
        >
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Filename</th>
                  <th>MIME / Size</th>
                  <th>SHA-256 Hash</th>
                  <th>RAG Status</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {documents.map((d) => (
                  <tr key={d.document_id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <FileText style={{ width: 15, height: 15, color: 'var(--accent-purple)', flexShrink: 0 }} />
                        <span
                          style={{
                            fontWeight: 600,
                            color: 'var(--text-primary)',
                            maxWidth: '200px',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                            display: 'block',
                          }}
                        >
                          {d.filename}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ color: 'var(--text-secondary)' }}>{d.mime_type}</div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                        {(d.file_size_bytes / 1024).toFixed(1)} KB
                      </div>
                    </td>
                    <td>
                      <div
                        title={d.integrity_hash}
                        style={{
                          fontFamily: "'JetBrains Mono', monospace",
                          fontSize: '0.6875rem',
                          color: 'var(--accent-cyan)',
                          maxWidth: '200px',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {d.integrity_hash}
                      </div>
                    </td>
                    <td>
                      <span className={`badge-tag ${d.processing_status === 'processed' ? 'badge-emerald' : 'badge-amber'}`}>
                        {d.processing_status === 'processed'
                          ? <Check style={{ width: 10, height: 10 }} />
                          : <RefreshCw style={{ width: 10, height: 10 }} />
                        }
                        {d.processing_status || 'uploaded'}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '6px' }}>
                        <button
                          onClick={() => handleProcessDocument(d.document_id)}
                          disabled={processingDocId === d.document_id}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '5px 10px', color: 'var(--accent-purple)' }}
                          title="Extract & Chunk Text for RAG"
                        >
                          <Play style={{ width: 11, height: 11 }} />
                          Process
                        </button>
                        <button
                          onClick={() => handleDownloadDocument(d.document_id, d.filename)}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '5px 10px' }}
                          title="Decrypt & Stream Download"
                        >
                          <Download style={{ width: 11, height: 11 }} />
                          Decrypt
                        </button>
                        <button
                          onClick={() => setDeleteDocId(d.document_id)}
                          className="btn btn-ghost"
                          style={{ padding: '5px 8px', color: 'var(--text-muted)' }}
                          title="Delete Document"
                          onMouseEnter={e => (e.currentTarget.style.color = '#f87171')}
                          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                        >
                          <Trash2 style={{ width: 13, height: 13 }} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Upload Modal */}
      {uploadModalOpen && (
        <div className="modal-backdrop">
          <div className="modal-panel" style={{ maxWidth: '460px' }}>
            <div className="modal-header">
              <h3 className="modal-title">Upload Encrypted Document</h3>
              <button
                onClick={() => setUploadModalOpen(false)}
                style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: 'transparent', border: 'none',
                  color: 'var(--text-muted)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 160ms',
                }}
                onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,0.06)'; e.currentTarget.style.color = 'var(--text-primary)'; }}
                onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = 'var(--text-muted)'; }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            <form onSubmit={handleUpload} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Drop zone */}
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  if (e.dataTransfer.files?.[0]) setUploadFile(e.dataTransfer.files[0]);
                }}
                style={{
                  borderRadius: '12px',
                  border: `2px dashed ${dragOver ? 'rgba(34,211,238,0.55)' : uploadFile ? 'rgba(16,185,129,0.40)' : 'rgba(255,255,255,0.12)'}`,
                  background: dragOver
                    ? 'rgba(34,211,238,0.05)'
                    : uploadFile ? 'rgba(16,185,129,0.04)' : 'rgba(255,255,255,0.02)',
                  padding: '28px 20px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'all 180ms ease',
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: '10px',
                }}
              >
                <CloudUpload style={{ width: 32, height: 32, color: uploadFile ? 'var(--accent-emerald)' : 'var(--accent-cyan)', opacity: 0.8 }} />
                <div style={{ fontSize: '0.8125rem', color: uploadFile ? 'var(--accent-emerald)' : 'var(--text-secondary)', fontWeight: 500 }}>
                  {uploadFile ? uploadFile.name : 'Drag & drop TXT, PDF, or DOCX file here'}
                </div>
                <input
                  type="file"
                  onChange={(e) => e.target.files?.[0] && setUploadFile(e.target.files[0])}
                  className="hidden"
                  id="file-input"
                />
                <label
                  htmlFor="file-input"
                  style={{
                    display: 'inline-block',
                    padding: '5px 14px',
                    borderRadius: '8px',
                    background: 'rgba(255,255,255,0.06)',
                    border: '1px solid rgba(255,255,255,0.10)',
                    fontSize: '0.75rem',
                    color: 'var(--accent-cyan)',
                    fontWeight: 600,
                    cursor: 'pointer',
                    transition: 'all 160ms',
                  }}
                >
                  Browse Files
                </label>
              </div>

              <div>
                <label className="form-label">Vault Unlock Password</label>
                <input
                  type="password"
                  value={vaultPassword}
                  onChange={(e) => setVaultPassword(e.target.value)}
                  placeholder="Password required to derive Master Key..."
                  style={inputStyle}
                  onFocus={e => { e.target.style.borderColor = 'rgba(34,211,238,0.45)'; e.target.style.boxShadow = '0 0 0 3px rgba(34,211,238,0.08)'; }}
                  onBlur={e => { e.target.style.borderColor = 'rgba(255,255,255,0.10)'; e.target.style.boxShadow = 'none'; }}
                />
              </div>

              {statusMsg && (
                <div style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', textAlign: 'center', fontWeight: 600 }}>
                  {statusMsg}
                </div>
              )}

              <div className="modal-footer" style={{ paddingTop: 0, marginTop: 0, border: 'none' }}>
                <button type="button" onClick={() => setUploadModalOpen(false)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" style={{ fontSize: '0.8rem' }}>
                  <Upload style={{ width: 13, height: 13 }} />
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
    </PageLayout>
  );
}
