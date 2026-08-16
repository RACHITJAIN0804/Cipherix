import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { CommandCenter } from './pages/CommandCenter';
import { DashboardView } from './pages/DashboardView';
import { VaultsView } from './pages/VaultsView';
import { DocumentsView } from './pages/DocumentsView';
import { AISearchView } from './pages/AISearchView';
import { AIAssistantView } from './pages/AIAssistantView';
import { IntegrityView } from './pages/IntegrityView';
import { ComputerAccessView } from './pages/ComputerAccessView';
import { ActivityLogView } from './pages/ActivityLogView';
import { SettingsView } from './pages/SettingsView';
import { SecurityView } from './pages/SecurityView';
import { RecoveryView } from './pages/RecoveryView';
import { AuthView } from './pages/AuthView';
import { CipherixAPI } from './api';

export function App() {
  const [user, setUser] = useState({
    username: localStorage.getItem("cipherix_username") || "rachit_admin",
    role: "Administrator"
  });

  const handleLogout = () => {
    CipherixAPI.setAuthToken("");
    localStorage.removeItem("cipherix_username");
    setUser(null);
  };

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  return (
    <BrowserRouter>
      <Routes>
        {/* Auth Route */}
        <Route path="/login" element={<AuthView onLoginSuccess={handleLoginSuccess} />} />

        {/* Main Command Center Dashboard */}
        <Route path="/" element={<CommandCenter user={user} onLogout={handleLogout} />} />

        {/* Feature Sub-Pages */}
        <Route path="/dashboard" element={<DashboardView user={user} onLogout={handleLogout} />} />
        <Route path="/vaults" element={<VaultsView user={user} onLogout={handleLogout} />} />
        <Route path="/documents" element={<DocumentsView user={user} onLogout={handleLogout} />} />
        <Route path="/search" element={<AISearchView user={user} onLogout={handleLogout} />} />
        <Route path="/assistant" element={<AIAssistantView user={user} onLogout={handleLogout} />} />
        <Route path="/integrity" element={<IntegrityView user={user} onLogout={handleLogout} />} />
        <Route path="/computer-access" element={<ComputerAccessView user={user} onLogout={handleLogout} />} />
        <Route path="/activity" element={<ActivityLogView user={user} onLogout={handleLogout} />} />

        {/* System Sub-Pages */}
        <Route path="/settings" element={<SettingsView user={user} onLogout={handleLogout} />} />
        <Route path="/security" element={<SecurityView user={user} onLogout={handleLogout} />} />
        <Route path="/recovery" element={<RecoveryView user={user} onLogout={handleLogout} />} />

        {/* Catch-all redirect to Command Center */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;
