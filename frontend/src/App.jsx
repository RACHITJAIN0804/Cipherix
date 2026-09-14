import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate } from 'react-router-dom';
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

function isAuthenticated() {
  const token = CipherixAPI.getAuthToken();
  const username = localStorage.getItem('cipherix_username');
  return !!(token && username);
}

function ProtectedRoute({ user, element }) {
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return element;
}

function AppRoutes({ user, setUser }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    CipherixAPI.setAuthToken('');
    localStorage.removeItem('cipherix_username');
    localStorage.removeItem('cipherix_token');
    setUser(null);
    navigate('/login', { replace: true });
  };

  const handleLoginSuccess = (userData) => {
    setUser(userData);
  };

  const pageProps = { user, onLogout: handleLogout };

  return (
    <Routes>
      <Route
        path="/login"
        element={
          user
            ? <Navigate to="/" replace />
            : <AuthView initialMode="login" onLoginSuccess={handleLoginSuccess} />
        }
      />
      <Route
        path="/register"
        element={
          user
            ? <Navigate to="/" replace />
            : <AuthView initialMode="register" onLoginSuccess={handleLoginSuccess} />
        }
      />

      <Route
        path="/"
        element={
          <ProtectedRoute
            user={user}
            element={<CommandCenter {...pageProps} />}
          />
        }
      />

      <Route path="/dashboard"      element={<ProtectedRoute user={user} element={<DashboardView      {...pageProps} />} />} />
      <Route path="/vaults"         element={<ProtectedRoute user={user} element={<VaultsView         {...pageProps} />} />} />
      <Route path="/documents"      element={<ProtectedRoute user={user} element={<DocumentsView      {...pageProps} />} />} />
      <Route path="/search"         element={<ProtectedRoute user={user} element={<AISearchView       {...pageProps} />} />} />
      <Route path="/assistant"      element={<ProtectedRoute user={user} element={<AIAssistantView    {...pageProps} />} />} />
      <Route path="/integrity"      element={<ProtectedRoute user={user} element={<IntegrityView      {...pageProps} />} />} />
      <Route path="/computer-access"element={<ProtectedRoute user={user} element={<ComputerAccessView {...pageProps} />} />} />
      <Route path="/activity"       element={<ProtectedRoute user={user} element={<ActivityLogView    {...pageProps} />} />} />

      <Route path="/settings" element={<ProtectedRoute user={user} element={<SettingsView {...pageProps} />} />} />
      <Route path="/security" element={<ProtectedRoute user={user} element={<SecurityView {...pageProps} />} />} />
      <Route path="/recovery" element={<ProtectedRoute user={user} element={<RecoveryView {...pageProps} />} />} />

      <Route path="*" element={<Navigate to={user ? '/' : '/login'} replace />} />
    </Routes>
  );
}

export function App() {
  const [user, setUser] = useState(() => {
    const token = CipherixAPI.getAuthToken();
    const username = localStorage.getItem('cipherix_username');
    if (token && username) {
      return { username, role: 'Administrator' };
    }
    return null;
  });

  return (
    <BrowserRouter>
      <AppRoutes user={user} setUser={setUser} />
    </BrowserRouter>
  );
}

export default App;
