import React, { useState } from 'react';
import { Shield, AlertCircle, ArrowRight, Lock, Sun, Moon } from 'lucide-react';

interface LoginViewProps {
  onSuccess: (email: string) => void;
  theme?: 'dark' | 'light';
  onToggleTheme?: () => void;
}

export default function LoginView({ onSuccess, theme, onToggleTheme }: LoginViewProps) {
  const [email, setEmail] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    // Validate xyzcomp.com domain
    const trimmedEmail = email.trim();
    const xyzcompRegex = /^[a-zA-Z0-9._%+-]+@xyzcomp\.com$/i;

    if (!trimmedEmail) {
      setError('Email field is required.');
      return;
    }

    if (!xyzcompRegex.test(trimmedEmail)) {
      setError('this is a invalid input');
      return;
    }

    setLoading(true);
    // Mimic quick credential check
    setTimeout(() => {
      setLoading(false);
      onSuccess(trimmedEmail);
    }, 600);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col justify-center items-center px-4 relative overflow-hidden select-none">
      {/* Soft Ambient Background Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] rounded-full bg-blue-550/5 blur-[100px] pointer-events-none"></div>
      
      {onToggleTheme && (
        <div className="w-full max-w-md z-10 flex justify-end mb-3">
          <button
            id="login-theme-toggle"
            onClick={onToggleTheme}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#0F131A] border border-slate-800 rounded-lg text-slate-400 hover:text-slate-100 font-mono text-[9px] uppercase tracking-wider font-bold transition-all cursor-pointer shadow-md"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="h-3 w-3 text-amber-500 animate-pulse" />
                <span>Light Mode</span>
              </>
            ) : (
              <>
                <Moon className="h-3 w-3 text-blue-500" />
                <span>Dark Mode</span>
              </>
            )}
          </button>
        </div>
      )}

      <div className="w-full max-w-md z-10">
        {/* Core Frame Card */}
        <div id="login-frame-card" className="bg-[#0F131A] border border-slate-800 rounded-2xl p-8 shadow-2xl relative overflow-hidden">
          
          {/* Subtle Accent top status bar */}
          <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-650 via-blue-500 to-indigo-650"></div>

          {/* Icon Header */}
          <div className="flex flex-col items-center text-center mb-8">
            <div className="w-12 h-12 bg-blue-600/10 border border-blue-500/20 rounded-xl flex items-center justify-center mb-4 text-blue-400">
              <Shield className="h-6 w-6" />
            </div>
            <h1 className="text-xl font-bold uppercase tracking-wider text-slate-100 flex items-center gap-2">
              SENTINEL <span className="text-blue-500 font-extrabold font-mono">ATT&CK</span>
            </h1>
            <p className="text-[10px] font-mono text-slate-500 tracking-widest mt-1 uppercase">
              Security Operations Terminal
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <div className="flex justify-between items-center mb-2">
                <label className="text-[10px] font-mono font-bold text-slate-400 uppercase tracking-widest">
                  xyzcomp Identity Mail Access
                </label>
                <span className="text-[9px] font-mono text-blue-400 uppercase font-semibold">
                  {/* Required domain: xyzcomp.com */}
                </span>
              </div>
              
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-slate-500">
                  <Lock className="h-4 w-4" />
                </div>
                <input
                  id="email-input"
                  type="text"
                  value={email}
                  onChange={(e) => {
                    setEmail(e.target.value);
                    if (error) setError('');
                  }}
                  placeholder="username@xyzcomp.com"
                  className="w-full bg-[#07090D] border border-slate-800 focus:border-blue-500 focus:ring-1 focus:ring-blue-500/30 text-slate-100 rounded-lg py-3 pl-10 pr-4 outline-none transition-all font-mono text-xs"
                  autoFocus
                />
              </div>
            </div>

            {error && (
              <div id="login-error-container" className="flex items-start gap-2 bg-red-950/20 border border-red-900/30 text-red-400 p-3 rounded-lg text-xs font-mono animate-fadeIn justify-center">
                <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
                <span className="font-bold select-text">{error}</span>
              </div>
            )}

            <button
              id="submit-login-button"
              type="submit"
              disabled={loading}
              className="w-full py-3 bg-blue-605 bg-blue-600 hover:bg-blue-500 disabled:bg-blue-800 disabled:opacity-50 text-slate-100 rounded-xl font-mono text-xs uppercase font-extrabold tracking-widest flex items-center justify-center gap-2 transition hover:-translate-y-0.5 active:translate-y-0 shadow-lg shadow-blue-500/10 cursor-pointer"
            >
              {loading ? (
                <span>Validating Key Domain...</span>
              ) : (
                <>
                  <span>Request Session Access</span>
                  <ArrowRight className="h-4 w-4" />
                </>
              )}
            </button>
          </form>

          <div className="mt-8 pt-6 border-t border-slate-850 text-center">
            <span className="text-[9px] font-mono text-slate-650 text-slate-600 tracking-wider uppercase block">
              Authorization level: Administrator Privilege Verification
            </span>
          </div>

        </div>

        {/* Footer info lockup */}
        <p className="text-center mt-6 text-[10px] font-mono text-slate-600 uppercase tracking-widest leading-relaxed">
          Operational Security Domain Policy <br />
          Restricted access. Authorized corporate personnel only.
        </p>
      </div>
    </div>
  );
}
