import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Shield, Lock, User, ArrowRight, CheckCircle2, AlertTriangle } from 'lucide-react';
import { CipherixAPI } from '../api';
import { PageTransition } from '../components/PageTransition';

export function AuthView({ onLoginSuccess }) {
  const navigate = useNavigate();
  const [isRegister, setIsRegister] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [successMsg, setSuccessMsg] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setSuccessMsg("");

    if (!username.trim() || !password.trim()) {
      setError("Username and password are required.");
      return;
    }

    if (isRegister && password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setLoading(true);

    try {
      if (isRegister) {
        // Register Endpoint
        await CipherixAPI.request('/auth/register', {
          method: 'POST',
          body: JSON.stringify({ username: username.trim(), password }),
        });
        setSuccessMsg("Registration successful! You can now log in.");
        setIsRegister(false);
        setPassword("");
        setConfirmPassword("");
      } else {
        // Login Endpoint
        const res = await CipherixAPI.request('/auth/login', {
          method: 'POST',
          body: JSON.stringify({ username: username.trim(), password }),
        });

        if (res.access_token) {
          CipherixAPI.setAuthToken(res.access_token);
          localStorage.setItem("cipherix_username", username.trim());
          if (onLoginSuccess) {
            onLoginSuccess({ username: username.trim(), role: "Administrator" });
          }
          navigate('/');
        } else {
          setError("Invalid login response from server.");
        }
      }
    } catch (err) {
      setError(err.message || "Authentication failed. Check credentials.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageTransition>
      <div className="min-h-screen bg-[#080B12] flex items-center justify-center p-6 relative overflow-hidden">
        {/* Background Ambient Glowing Orbs */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="absolute bottom-1/4 left-1/3 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl pointer-events-none"></div>

        <div className="glass-panel max-w-md w-full p-8 space-y-6 relative border-slate-800 z-10">
          {/* Header */}
          <div className="text-center space-y-2">
            <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center mx-auto mb-3">
              <Shield className="w-8 h-8" />
            </div>
            <h1 className="text-2xl font-extrabold font-outfit text-slate-100 tracking-wide">
              {isRegister ? 'Create Cipherix Account' : 'Authenticate Session'}
            </h1>
            <p className="text-xs text-slate-400">
              {isRegister ? 'Register credentials for zero-knowledge vault access' : 'Enter credentials to access your encrypted command center'}
            </p>
          </div>

          {error && (
            <div className="p-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {successMsg && (
            <div className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          {/* Form */}
          <form onSubmit={handleSubmit} className="space-y-4 text-xs">
            <div>
              <label className="block font-bold uppercase text-slate-400 mb-1">Username</label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="e.g. rachit_admin"
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-10 pr-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="block font-bold uppercase text-slate-400 mb-1">Password</label>
              <div className="relative">
                <Lock className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter password..."
                  className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-10 pr-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            {isRegister && (
              <div>
                <label className="block font-bold uppercase text-slate-400 mb-1">Confirm Password</label>
                <div className="relative">
                  <Lock className="w-4 h-4 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="Confirm password..."
                    className="w-full bg-slate-900 border border-slate-800 rounded-xl pl-10 pr-3 py-2.5 text-xs text-slate-100 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-purple-600 text-black font-bold text-xs flex items-center justify-center gap-2 hover:opacity-90 transition-opacity shadow-lg shadow-cyan-500/20"
            >
              <span>{loading ? 'Authenticating...' : isRegister ? 'Register Account' : 'Authenticate Session'}</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>

          {/* Toggle Switch */}
          <div className="text-center pt-2 border-t border-slate-800 text-xs text-slate-400">
            {isRegister ? (
              <span>Already have an account? <button onClick={() => { setIsRegister(false); setError(""); }} className="text-cyan-400 font-bold hover:underline">Log in</button></span>
            ) : (
              <span>Need a new account? <button onClick={() => { setIsRegister(true); setError(""); }} className="text-cyan-400 font-bold hover:underline">Register</button></span>
            )}
          </div>
        </div>
      </div>
    </PageTransition>
  );
}
