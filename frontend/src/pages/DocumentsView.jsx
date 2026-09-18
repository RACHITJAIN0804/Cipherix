import React, { useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { PageLayout } from '../components/PageLayout';
import { PageHeader } from '../components/PageHeader';
import { LoadingState, EmptyState, ErrorState, ConfirmDialog, VaultSelector } from '../components/CommonUI';
import { CipherixAPI } from '../api';
import { FileText, Download, Check, Upload, Trash2, Play, RefreshCw, X, CloudUpload, ShieldCheck, AlertTriangle, CheckCircle2, Copy, Clock, Database, Link, HardDrive } from 'lucide-react';

export function DocumentsView({ user, onLogout }) {
  const navigate = useNavigate();
  const location = useLocation();
  const [vaults, setVaults] = useState([]);
  const [selectedVaultId, setSelectedVaultId] = useState(() => location.state?.vaultId || '');
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

  // Verification Modal State
  const [verifyingDoc, setVerifyingDoc] = useState(null);
  const [verifyingLoading, setVerifyingLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyError, setVerifyError] = useState(null);
  const [copiedHash, setCopiedHash] = useState(false);

  useEffect(() => {
    if (location.state?.vaultId) {
      setSelectedVaultId(location.state.vaultId);
    }
  }, [location.state]);

  const fetchVaultsAndDocs = async () => {
    setLoading(true);
    setError('');
    try {
      const vaultList = await CipherixAPI.request('/vaults');
      const vArray = Array.isArray(vaultList) ? vaultList : [];
      setVaults(vArray);

      if (vArray.length === 0) {
        setDocuments([]);
        setSelectedVaultId('');
        return;
      }

      const targetVaultId = selectedVaultId && vArray.some(v => v.vault_id === selectedVaultId)
        ? selectedVaultId
        : vArray[0].vault_id;

      if (targetVaultId !== selectedVaultId) {
        setSelectedVaultId(targetVaultId);
      }

      if (targetVaultId) {
        const docList = await CipherixAPI.request(`/vaults/${targetVaultId}/documents`);
        const docs = docList?.documents
          ? (Array.isArray(docList.documents) ? docList.documents : [])
          : (Array.isArray(docList) ? docList : []);
        setDocuments(docs);
      } else {
        setDocuments([]);
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

  const handleVerifyDocument = async (doc) => {
    setVerifyingDoc(doc);
    setVerifyingLoading(true);
    setVerifyResult(null);
    setVerifyError(null);
    try {
      const res = await CipherixAPI.request('/blockchain/verify', {
        method: 'POST',
        body: JSON.stringify({ vault_id: selectedVaultId, document_id: doc.document_id }),
      });
      setVerifyResult(res);
    } catch (err) {
      setVerifyError(err.message || 'Verification failed.');
    } finally {
      setVerifyingLoading(false);
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
                          {d.original_filename || d.filename || 'Untitled'}
                        </span>
                      </div>
                    </td>
                    <td>
                      <div style={{ color: 'var(--text-secondary)' }}>{d.mime_type}</div>
                      <div style={{ fontSize: '0.6875rem', color: 'var(--text-muted)' }}>
                        {(((d.size ?? d.file_size_bytes ?? 0)) / 1024).toFixed(1)} KB
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
                        {d.integrity_hash || '-'}
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
                          onClick={() => handleVerifyDocument(d)}
                          className="btn btn-secondary"
                          style={{ fontSize: '0.75rem', padding: '5px 10px', color: 'var(--accent-amber)' }}
                          title="Verify Blockchain Integrity"
                        >
                          <ShieldCheck style={{ width: 11, height: 11 }} />
                          Verify
                        </button>
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
                          onClick={() => handleDownloadDocument(d.document_id, d.original_filename || d.filename || 'download')}
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

      {}
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
              {}
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

      {}
      <ConfirmDialog
        isOpen={!!deleteDocId}
        title="Delete Encrypted Document"
        message="Are you sure you want to permanently delete this document binary blob and its SHA-256 integrity metadata?"
        confirmLabel="Delete Document"
        onConfirm={handleDeleteDocument}
        onCancel={() => setDeleteDocId(null)}
      />

      {/* Blockchain Verification Modal */}
      {verifyingDoc && (
        <div className="modal-backdrop">
          <div className="modal-panel" style={{ maxWidth: '560px', width: '90%' }}>
            <div className="modal-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldCheck style={{ width: 18, height: 18, color: 'var(--accent-amber)' }} />
                <h3 className="modal-title">Blockchain Integrity Verification</h3>
              </div>
              <button
                onClick={() => setVerifyingDoc(null)}
                style={{
                  width: 30, height: 30, borderRadius: 8,
                  background: 'transparent', border: 'none',
                  color: 'var(--text-muted)', cursor: 'pointer',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}
              >
                <X style={{ width: 16, height: 16 }} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px', padding: '10px 0' }}>
              <div style={{ fontSize: '0.8125rem', color: 'var(--text-secondary)' }}>
                Target Document: <strong style={{ color: 'var(--text-primary)' }}>{verifyingDoc.original_filename || verifyingDoc.filename || 'Untitled'}</strong>
              </div>

              {verifyingLoading ? (
                <div style={{ padding: '32px', textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '12px' }}>
                  <RefreshCw style={{ width: 28, height: 28, color: 'var(--accent-amber)', animation: 'spin 1s linear infinite' }} />
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', fontWeight: 500 }}>
                    Recalculating SHA-256 hash & verifying on-chain...
                  </div>
                </div>
              ) : verifyError ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                  <div
                    style={{
                      display: 'flex', alignItems: 'center', gap: '10px', padding: '14px',
                      borderRadius: '10px', border: '1px solid rgba(239,68,68,0.35)',
                      background: 'rgba(239,68,68,0.08)', color: '#fca5a5', fontSize: '0.85rem', fontWeight: 600
                    }}
                  >
                    <AlertTriangle style={{ width: 18, height: 18, flexShrink: 0 }} />
                    <span>{verifyError}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
                    <button onClick={() => handleVerifyDocument(verifyingDoc)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
                      Retry
                    </button>
                  </div>
                </div>
              ) : verifyResult ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div
                    style={{
                      display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 16px',
                      borderRadius: '10px',
                      border: `1px solid ${verifyResult.verified ? 'rgba(16,185,129,0.35)' : 'rgba(239,68,68,0.35)'}`,
                      background: verifyResult.verified ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
                      color: verifyResult.verified ? '#6ee7b7' : '#fca5a5',
                      fontWeight: 700, fontSize: '0.875rem'
                    }}
                  >
                    {verifyResult.verified
                      ? <CheckCircle2 style={{ width: 20, height: 20, flexShrink: 0 }} />
                      : <AlertTriangle style={{ width: 20, height: 20, flexShrink: 0 }} />
                    }
                    <div>
                      <div>{verifyResult.verified ? 'VERIFIED & UNTAMPERED' : 'INTEGRITY MISMATCH DETECTED'}</div>
                      <div style={{ fontSize: '0.75rem', fontWeight: 400, opacity: 0.9, marginTop: '2px' }}>
                        {verifyResult.message || (verifyResult.verified ? 'Hash matches blockchain record.' : 'Local hash does not match on-chain anchor.')}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '12px' }}>
                    <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(7,10,18,0.55)', border: '1px solid rgba(255,255,255,0.07)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                        <HardDrive style={{ width: 12, height: 12, color: 'var(--accent-cyan)' }} />
                        Recalculated File SHA-256
                      </div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6875rem', color: 'var(--accent-cyan)', marginTop: '4px', wordBreak: 'break-all' }}>
                        {verifyResult.current_hash || verifyResult.current_integrity_hash || '-'}
                      </div>
                    </div>

                    <div style={{ padding: '12px 14px', borderRadius: '10px', background: 'rgba(7,10,18,0.55)', border: '1px solid rgba(255,255,255,0.07)' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600 }}>
                        <Link style={{ width: 12, height: 12, color: 'var(--accent-amber)' }} />
                        On-Chain Anchor Hash
                      </div>
                      <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.6875rem', color: 'var(--accent-amber)', marginTop: '4px', wordBreak: 'break-all' }}>
                        {verifyResult.blockchain_hash || verifyResult.stored_integrity_hash || '-'}
                      </div>
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: '10px', fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Network: </span>
                      <span className="badge-tag badge-purple" style={{ fontSize: '0.6875rem' }}>{verifyResult.network || 'local-development'}</span>
                    </div>
                    <div>
                      <span style={{ color: 'var(--text-muted)' }}>Transaction: </span>
                      <span style={{ fontFamily: "'JetBrains Mono', monospace", color: 'var(--text-primary)' }}>
                        {verifyResult.tx_hash ? `${verifyResult.tx_hash.slice(0, 10)}...` : '-'}
                      </span>
                    </div>
                    {verifyResult.verified_at && (
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Verified At: </span>
                        <span style={{ color: 'var(--text-primary)' }}>{new Date(verifyResult.verified_at).toLocaleTimeString()}</span>
                      </div>
                    )}
                  </div>
                </div>
              ) : null}
            </div>

            <div className="modal-footer" style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '12px', marginTop: '8px' }}>
              <button onClick={() => setVerifyingDoc(null)} className="btn btn-secondary" style={{ fontSize: '0.8rem' }}>
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </PageLayout>
  );
}
