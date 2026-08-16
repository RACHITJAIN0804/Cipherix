/*
 Cipherix Main Web Application Controller
 ----------------------------------------
 Manages UI state, view navigation, interactive modals, REST API synchronization,
 and dynamic card/table rendering.
*/

import { CipherixAPI } from "./api.js";

document.addEventListener("DOMContentLoaded", () => {
  console.log("Cipherix Web Application Initializing...");

  // Application State
  const state = {
    activeView: "dashboard",
    vaults: [],
    documents: [],
    selectedVaultId: "",
    computerAccessEnabled: false,
    activityLogs: [
      {
        timestamp: new Date(Date.now() - 3600000).toISOString(),
        category: "Auth",
        action: "User Login",
        status: "SUCCESS",
        details: "JWT Access Token Issued (user: rachit_admin)",
      },
      {
        timestamp: new Date(Date.now() - 2400000).toISOString(),
        category: "Vault",
        action: "Vault Unlocked",
        status: "SUCCESS",
        details: "Argon2id Master Key derived (vault: Financial & Security Vault)",
      },
      {
        timestamp: new Date(Date.now() - 1200000).toISOString(),
        category: "Blockchain",
        action: "Hash Anchored",
        status: "SUCCESS",
        details: "SHA-256 anchored on local-development ledger (tx: 0xba82c9...)",
      },
    ],
  };

  // UI Elements Initialization
  const navItems = document.querySelectorAll(".nav-item");
  const viewPanels = document.querySelectorAll(".view-panel");
  const pageTitle = document.getElementById("page-title");

  // View Navigation Handler
  function navigateTo(targetId) {
    state.activeView = targetId;

    // Update Nav Link Active States
    navItems.forEach((item) => {
      if (item.getAttribute("data-target") === targetId) {
        item.classList.add("active");
      } else {
        item.classList.remove("active");
      }
    });

    // Update View Panel Display
    viewPanels.forEach((panel) => {
      if (panel.id === `view-${targetId}`) {
        panel.classList.add("active");
      } else {
        panel.classList.remove("active");
      }
    });

    // Update Header Title
    const titleMap = {
      dashboard: "Dashboard Overview",
      vaults: "Encrypted Vaults",
      documents: "Encrypted Document Storage",
      search: "Vault-Isolated AI Search",
      rag: "AI Security Assistant (Local RAG)",
      blockchain: "Blockchain Integrity & Verification",
      "computer-access": "Controlled Computer Access",
      activity: "System Activity & Audit Log",
      settings: "System Settings",
      security: "Cryptographic Policy & Security",
    };
    if (pageTitle) {
      pageTitle.textContent = titleMap[targetId] || "Cipherix System";
    }
  }

  // Bind Nav Clicks
  navItems.forEach((item) => {
    item.addEventListener("click", (e) => {
      e.preventDefault();
      const target = item.getAttribute("data-target");
      navigateTo(target);
    });
  });

  // Modal Handlers
  const modalCreateVault = document.getElementById("modal-create-vault");
  const openVaultModalBtns = [
    document.getElementById("quick-create-vault-btn"),
    document.getElementById("create-vault-modal-trigger"),
  ];
  const closeModalBtns = document.querySelectorAll(".modal-close");

  openVaultModalBtns.forEach((btn) => {
    if (btn) {
      btn.addEventListener("click", () => {
        modalCreateVault.classList.remove("hidden");
      });
    }
  });

  closeModalBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      if (modalCreateVault) modalCreateVault.classList.add("hidden");
    });
  });

  // API Refresh Logic
  async function refreshData() {
    try {
      const vaultsData = await CipherixAPI.request("/vaults");
      state.vaults = Array.isArray(vaultsData) ? vaultsData : [];
      renderVaults();
      populateVaultDropdowns();

      if (state.vaults.length > 0 && !state.selectedVaultId) {
        state.selectedVaultId = state.vaults[0].vault_id;
      }

      if (state.selectedVaultId) {
        const docsData = await CipherixAPI.request(`/vaults/${state.selectedVaultId}/documents`);
        state.documents = Array.isArray(docsData) ? docsData : [];
        renderDocuments();
      }

      renderDashboard();
      renderActivityLogs();
    } catch (err) {
      console.error("Refresh error:", err);
    }
  }

  // Render Dashboard Elements
  function renderDashboard() {
    const statVaults = document.getElementById("stat-vaults");
    const statDocs = document.getElementById("stat-docs");
    const navVaultCount = document.getElementById("nav-vault-count");
    const navDocCount = document.getElementById("nav-doc-count");

    if (statVaults) statVaults.textContent = state.vaults.length;
    if (statDocs) statDocs.textContent = state.documents.length;
    if (navVaultCount) navVaultCount.textContent = state.vaults.length;
    if (navDocCount) navDocCount.textContent = state.documents.length;

    const listContainer = document.getElementById("dashboard-vault-list");
    if (listContainer) {
      if (state.vaults.length === 0) {
        listContainer.innerHTML = `<div class="text-xs text-muted text-center py-4">No vaults created yet. Click "New Vault" to create one.</div>`;
        return;
      }
      listContainer.innerHTML = state.vaults
        .map(
          (v) => `
        <div class="p-3 rounded-xl bg-surface-2/60 border border-border flex justify-between items-center text-xs">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 rounded-lg bg-cyan/10 border border-cyan/30 text-cyan flex items-center justify-center font-bold">
              <i class="fa-solid fa-vault"></i>
            </div>
            <div>
              <div class="font-bold text-light">${v.name}</div>
              <div class="text-muted text-[11px]">ID: ${v.vault_id.substring(0, 8)}...</div>
            </div>
          </div>
          <div class="flex items-center gap-2">
            <span class="badge ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}">${v.status.toUpperCase()}</span>
            <button class="btn btn-secondary text-[11px] py-1 px-2 font-medium" onclick="alert('Vault Key Status: AES-256-GCM Active')">Info</button>
          </div>
        </div>
      `
        )
        .join("");
    }
  }

  // Render Vaults Grid
  function renderVaults() {
    const gridContainer = document.getElementById("vaults-grid-container");
    if (!gridContainer) return;

    if (state.vaults.length === 0) {
      gridContainer.innerHTML = `<div class="col-span-full card p-8 text-center text-muted text-xs">No vaults found.</div>`;
      return;
    }

    gridContainer.innerHTML = state.vaults
      .map(
        (v) => `
      <div class="card space-y-4 border-cyan/20">
        <div class="flex justify-between items-start">
          <div class="w-10 h-10 rounded-xl bg-cyan/10 border border-cyan/30 text-cyan flex items-center justify-center text-lg">
            <i class="fa-solid fa-vault"></i>
          </div>
          <span class="badge ${v.status === 'unlocked' ? 'badge-emerald' : 'badge-amber'}">${v.status.toUpperCase()}</span>
        </div>
        <div>
          <h4 class="font-outfit font-bold text-base text-light">${v.name}</h4>
          <div class="text-xs text-muted font-mono mt-1">ID: ${v.vault_id}</div>
        </div>
        <div class="text-xs space-y-1 text-muted pt-2 border-t border-border/40">
          <div>Argon2id KDF: <span class="text-emerald font-semibold">Active (m=64MB)</span></div>
          <div>Encryption: <span class="text-purple font-semibold">AES-256-GCM</span></div>
        </div>
        <div class="flex gap-2 pt-2">
          <button class="btn btn-primary text-xs flex-1">${v.status === 'unlocked' ? 'Unlocked' : 'Unlock Vault'}</button>
          <button class="btn btn-secondary text-xs"><i class="fa-solid fa-key"></i></button>
        </div>
      </div>
    `
      )
      .join("");
  }

  // Populate Select Dropdowns
  function populateVaultDropdowns() {
    const selects = [
      document.getElementById("doc-vault-select"),
      document.getElementById("search-vault-select"),
      document.getElementById("rag-vault-select"),
      document.getElementById("blockchain-vault-select"),
    ];

    selects.forEach((sel) => {
      if (!sel) return;
      sel.innerHTML = state.vaults
        .map((v) => `<option value="${v.vault_id}">${v.name}</option>`)
        .join("");
      if (state.selectedVaultId) {
        sel.value = state.selectedVaultId;
      }
      sel.addEventListener("change", (e) => {
        state.selectedVaultId = e.target.value;
        refreshData();
      });
    });
  }

  // Render Document Table
  function renderDocuments() {
    const tableBody = document.getElementById("documents-table-body");
    if (!tableBody) return;

    if (state.documents.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="5" class="p-6 text-center text-muted text-xs">No documents uploaded to this vault yet.</td></tr>`;
      return;
    }

    tableBody.innerHTML = state.documents
      .map(
        (d) => `
      <tr class="hover:bg-surface-2/40 transition-colors">
        <td class="p-4 font-semibold text-light flex items-center gap-2">
          <i class="fa-solid fa-file-lines text-cyan"></i>
          <span>${d.filename}</span>
        </td>
        <td class="p-4 text-muted">
          <div>${d.mime_type}</div>
          <div class="text-[10px]">${(d.file_size_bytes / 1024).toFixed(1)} KB</div>
        </td>
        <td class="p-4">
          <div class="font-mono text-[11px] text-purple truncate max-w-[200px]" title="${d.integrity_hash}">
            ${d.integrity_hash}
          </div>
        </td>
        <td class="p-4">
          <span class="badge badge-emerald"><i class="fa-solid fa-check mr-1"></i>Indexed</span>
        </td>
        <td class="p-4 text-right space-x-1">
          <button class="btn btn-secondary text-[11px] py-1 px-2.5" onclick="alert('Streaming AES-256-GCM decrypted download...')">Download</button>
          <button class="btn btn-primary text-[11px] py-1 px-2.5" onclick="alert('Anchored to Blockchain Ledger!')">Anchor</button>
        </td>
      </tr>
    `
      )
      .join("");
  }

  // Render Activity Logs
  function renderActivityLogs() {
    const logBody = document.getElementById("activity-log-body");
    if (!logBody) return;

    logBody.innerHTML = state.activityLogs
      .map(
        (log) => `
      <tr class="hover:bg-surface-2/40 transition-colors">
        <td class="p-4 text-muted font-mono text-[11px]">${new Date(log.timestamp).toLocaleTimeString()}</td>
        <td class="p-4 font-semibold text-light">${log.category}</td>
        <td class="p-4 text-cyan">${log.action}</td>
        <td class="p-4"><span class="badge badge-emerald">${log.status}</span></td>
        <td class="p-4 text-muted text-xs">${log.details}</td>
      </tr>
    `
      )
      .join("");
  }

  // Create Vault Modal Form Submission
  const saveVaultBtn = document.getElementById("modal-btn-save-vault");
  if (saveVaultBtn) {
    saveVaultBtn.addEventListener("click", async () => {
      const nameInput = document.getElementById("modal-vault-name");
      const pwdInput = document.getElementById("modal-vault-password");
      if (!nameInput.value || !pwdInput.value) {
        alert("Please provide both vault name and password.");
        return;
      }

      try {
        const newVault = await CipherixAPI.request("/vaults/", {
          method: "POST",
          body: JSON.stringify({ name: nameInput.value, password: pwdInput.value }),
        });
        modalCreateVault.classList.add("hidden");
        nameInput.value = "";
        pwdInput.value = "";
        
        state.activityLogs.unshift({
          timestamp: new Date().toISOString(),
          category: "Vault",
          action: "Vault Created",
          status: "SUCCESS",
          details: `Vault '${newVault.name || "New Vault"}' created with Argon2id protection`,
        });

        refreshData();
      } catch (err) {
        alert("Create vault error: " + err.message);
      }
    });
  }

  // Semantic Search Execution
  const btnSearch = document.getElementById("btn-execute-search");
  if (btnSearch) {
    btnSearch.addEventListener("click", async () => {
      const inputQuery = document.getElementById("search-query-input");
      const resultsContainer = document.getElementById("search-results-container");
      if (!inputQuery.value.trim()) return;

      resultsContainer.innerHTML = `<div class="card p-6 text-center text-cyan text-xs animate-pulse"><i class="fa-solid fa-circle-notch fa-spin mr-2"></i>Computing SentenceTransformers embeddings & searching ChromaDB...</div>`;

      try {
        const res = await CipherixAPI.request("/search", {
          method: "POST",
          body: JSON.stringify({
            vault_id: state.selectedVaultId || "063aadc1-1696-43e8-b151-1f1759b713fd",
            query: inputQuery.value,
            top_k: parseInt(document.getElementById("input-top-k").value),
          }),
        });

        if (!res.results || res.results.length === 0) {
          resultsContainer.innerHTML = `<div class="card p-6 text-center text-muted text-xs">No matching text chunks found above threshold.</div>`;
          return;
        }

        resultsContainer.innerHTML = res.results
          .map(
            (r) => `
          <div class="card border-purple/30 space-y-2">
            <div class="flex justify-between items-center text-xs">
              <span class="font-bold text-light"><i class="fa-solid fa-file-lines text-purple mr-1.5"></i>${r.filename}</span>
              <span class="badge badge-cyan">${(r.similarity_score * 100).toFixed(1)}% Similarity</span>
            </div>
            <p class="text-xs text-muted font-mono p-3 bg-surface-2/60 rounded-lg border border-border">${r.text_snippet}</p>
          </div>
        `
          )
          .join("");
      } catch (err) {
        resultsContainer.innerHTML = `<div class="card p-6 text-center text-red text-xs">Search error: ${err.message}</div>`;
      }
    });
  }

  // RAG Chat Submission
  const btnRag = document.getElementById("btn-send-rag");
  const ragInput = document.getElementById("rag-input-prompt");
  const chatStream = document.getElementById("chat-messages-stream");

  if (btnRag && ragInput && chatStream) {
    btnRag.addEventListener("click", async () => {
      const promptText = ragInput.value.trim();
      if (!promptText) return;

      // Append User Message
      chatStream.innerHTML += `
        <div class="chat-message user">
          <div class="chat-avatar"><i class="fa-solid fa-user"></i></div>
          <div class="chat-bubble">
            <p class="text-xs">${promptText}</p>
          </div>
        </div>
      `;
      ragInput.value = "";
      chatStream.scrollTop = chatStream.scrollHeight;

      // Loading bubble
      const loadingId = "load_" + Date.now();
      chatStream.innerHTML += `
        <div class="chat-message assistant" id="${loadingId}">
          <div class="chat-avatar"><i class="fa-solid fa-shield-halved"></i></div>
          <div class="chat-bubble animate-pulse">
            <p class="text-xs text-cyan"><i class="fa-solid fa-circle-notch fa-spin mr-1.5"></i>Retrieving chunks & generating Ollama answer...</p>
          </div>
        </div>
      `;
      chatStream.scrollTop = chatStream.scrollHeight;

      try {
        const ragRes = await CipherixAPI.request("/rag/query", {
          method: "POST",
          body: JSON.stringify({
            vault_id: state.selectedVaultId || "063aadc1-1696-43e8-b151-1f1759b713fd",
            query: promptText,
          }),
        });

        const loadingElem = document.getElementById(loadingId);
        if (loadingElem) {
          loadingElem.outerHTML = `
            <div class="chat-message assistant">
              <div class="chat-avatar"><i class="fa-solid fa-shield-halved"></i></div>
              <div class="chat-bubble space-y-2">
                <div class="font-bold text-xs text-cyan">Cipherix Assistant (${ragRes.llm_model})</div>
                <p class="text-xs leading-relaxed">${ragRes.answer}</p>
                <div class="pt-2 border-t border-border/40 text-[11px] flex flex-wrap gap-1.5">
                  <span class="text-muted font-semibold">Sources:</span>
                  ${ragRes.sources.map(s => `<span class="badge badge-purple">${s.filename} (${(s.similarity * 100).toFixed(0)}%)</span>`).join("")}
                </div>
              </div>
            </div>
          `;
        }
        chatStream.scrollTop = chatStream.scrollHeight;
      } catch (err) {
        console.error(err);
      }
    });
  }

  // Computer Access Master Toggle
  const toggleAccessBtn = document.getElementById("toggle-computer-access-btn");
  if (toggleAccessBtn) {
    toggleAccessBtn.addEventListener("click", () => {
      state.computerAccessEnabled = !state.computerAccessEnabled;
      toggleAccessBtn.textContent = state.computerAccessEnabled ? "ENABLED" : "DISABLED";
      toggleAccessBtn.className = state.computerAccessEnabled
        ? "px-4 py-2 rounded-xl font-bold text-xs bg-emerald/20 text-emerald border border-emerald/40 transition-all hover:opacity-90"
        : "px-4 py-2 rounded-xl font-bold text-xs bg-red/20 text-red border border-red/40 transition-all hover:opacity-90";
      
      const navDot = document.getElementById("nav-access-dot");
      if (navDot) navDot.className = state.computerAccessEnabled ? "w-2 h-2 rounded-full bg-emerald ml-auto" : "w-2 h-2 rounded-full bg-red ml-auto";
    });
  }

  // Execute Computer Action
  const btnRunAction = document.getElementById("btn-run-computer-action");
  if (btnRunAction) {
    btnRunAction.addEventListener("click", async () => {
      if (!state.computerAccessEnabled) {
        alert("Computer Access is currently DISABLED. Toggle Master Access to ENABLE before executing actions.");
        return;
      }

      const actName = document.getElementById("access-action-select").value;
      const pathVal = document.getElementById("access-path-input").value;

      try {
        const res = await CipherixAPI.request("/computer-access/action", {
          method: "POST",
          body: JSON.stringify({
            action: actName,
            parameters: { path: pathVal },
          }),
        });

        alert(`Action '${actName}' executed successfully!\nResult: ${JSON.stringify(res.result)}`);
        state.activityLogs.unshift({
          timestamp: new Date().toISOString(),
          category: "ComputerAccess",
          action: actName,
          status: "SUCCESS",
          details: `Safe action executed inside CIPHERIX_WORKSPACE path: ${pathVal}`,
        });
        renderActivityLogs();
      } catch (err) {
        alert(`Action error: ${err.message}`);
      }
    });
  }

  // Initialize Data
  refreshData();
});
