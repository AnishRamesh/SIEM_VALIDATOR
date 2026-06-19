import React, { useState, useEffect } from 'react';
import { Shield, LayoutDashboard, Terminal, Table, Server, RefreshCw, KeyRound, CheckCircle2, Sun, Moon } from 'lucide-react';
import { CorrelationRule, DashboardStats, SystemStatus, TacticCoverage } from './types';
import MetricCards from './components/MetricCards';
import SystemStatusCard from './components/SystemStatusCard';
import RuleValidationTable from './components/RuleValidationTable';
import TacticHeatmap from './components/TacticHeatmap';
import SiemIntegration from './components/SiemIntegration';
import LoginView from './components/LoginView';

export default function App() {
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('app_theme') as 'dark' | 'light') || 'dark';
  });
  const [userEmail, setUserEmail] = useState<string | null>(() => {
    return localStorage.getItem('xyzcomp_authed_user') || null;
  });
  const [activeTab, setActiveTab] = useState<'dashboard' | 'rules' | 'integration'>('dashboard');
  const [loading, setLoading] = useState(true);
  const [rules, setRules] = useState<CorrelationRule[]>([]);
  const [coverage, setCoverage] = useState<TacticCoverage[]>([]);
  const [stats, setStats] = useState<DashboardStats>({
    totalRules: 0,
    correctRules: 0,
    needsFixRules: 0,
    unassignedRules: 0,
    averageConfidence: 0
  });
  const [systemStatus, setSystemStatus] = useState<SystemStatus>({
    connected: false,
    platform: 'Disconnected',
    ruleEngineVersion: 'v2.4.1',
    databaseStatus: 'Offline',
    lastSyncTime: null,
    ruleCount: 0
  });
  const [statusFilter, setStatusFilter] = useState('All');
  const [useCaseFilter, setUseCaseFilter] = useState<'All' | 'UC' | 'UAT' | 'threat'>('All');

  const handleLoginSuccess = (email: string) => {
    localStorage.setItem('xyzcomp_authed_user', email);
    setUserEmail(email);
  };

  const handleLogout = () => {
    localStorage.removeItem('xyzcomp_authed_user');
    setUserEmail(null);
  };

  const handleMetricCardClick = (cardId: string) => {
    if (cardId === 'metric-total-rules') {
      setStatusFilter('All');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-validated-accurate') {
      setStatusFilter('CORRECT');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-requires-remediation') {
      setStatusFilter('NEEDS_FIX');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-unassigned-rules') {
      setStatusFilter('UNASSIGNED');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-missing-techniques') {
      setStatusFilter('MISSING_TECHNIQUE');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-missing-subtechniques') {
      setStatusFilter('MISSING_SUB_TECHNIQUE');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-missing-mapping') {
      setStatusFilter('UNMAPPED');
      setUseCaseFilter('All');
      setActiveTab('rules');
    } else if (cardId === 'metric-use-cases') {
      setStatusFilter('All');
      setActiveTab('rules');
    }
  };

  const fetchAllData = async () => {
    try {
      const [rulesRes, statsRes, statusRes, coverageRes] = await Promise.all([
        fetch('/api/rules'),
        fetch('/api/dashboard/stats'),
        fetch('/api/dashboard/system-status'),
        fetch('/api/heatmap/coverage')
      ]);

      const [rulesData, statsData, statusData, coverageData] = await Promise.all([
        rulesRes.json(),
        statsRes.json(),
        statusRes.json(),
        coverageRes.json()
      ]);

      setRules(rulesData);
      setStats(statsData);
      setSystemStatus(statusData);
      setCoverage(coverageData);
    } catch (err) {
      console.error('Failed to load analytical analytical data from database.', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('app_theme', theme);
  }, [theme]);

  if (!userEmail) {
    return (
      <LoginView 
        onSuccess={handleLoginSuccess} 
        theme={theme} 
        onToggleTheme={() => setTheme(prev => prev === 'dark' ? 'light' : 'dark')} 
      />
    );
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 flex flex-col selection:bg-blue-600 selection:text-slate-100 font-sans">
      {/* Upper Navigation Header */}
      <header className="h-14 border-b border-slate-800 bg-[#0F131A] px-6 flex items-center justify-between z-44 sticky top-0">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center font-bold text-white shadow-lg shadow-blue-500/20">
            A
          </div>
          <div>
            <h1 className="text-md font-semibold tracking-tight uppercase flex items-center gap-1.5">
              SENTINEL <span className="text-blue-500">ATT&CK</span> MAPPER
            </h1>
          </div>
          <span className="text-[10px] font-mono text-slate-500 bg-slate-900/40 px-2 py-0.5 rounded border border-slate-800 hidden sm:inline-block">
            V14.1 LIVE
          </span>
        </div>

        {/* Navigation Control Buttons */}
        <div className="flex items-center gap-4">
          <nav className="flex items-center bg-slate-950 p-0.5 rounded-lg border border-slate-800">
            <button
              onClick={() => setActiveTab('dashboard')}
              className={`flex items-center space-x-1.5 font-mono text-[10px] uppercase tracking-wider font-bold py-1.5 px-3 rounded transition-all cursor-pointer ${
                activeTab === 'dashboard'
                  ? 'bg-blue-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <LayoutDashboard className="h-3 w-3" />
              <span className="hidden md:inline">Heatmap</span>
            </button>
            
            <button
              onClick={() => setActiveTab('rules')}
              className={`flex items-center space-x-1.5 font-mono text-[10px] uppercase tracking-wider font-bold py-1.5 px-3 rounded transition-all cursor-pointer ${
                activeTab === 'rules'
                  ? 'bg-blue-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <Table className="h-3 w-3" />
              <span className="hidden md:inline">Queue</span>
            </button>

            <button
              onClick={() => setActiveTab('integration')}
              className={`flex items-center space-x-1.5 font-mono text-[10px] uppercase tracking-wider font-bold py-1.5 px-3 rounded transition-all cursor-pointer ${
                activeTab === 'integration'
                  ? 'bg-blue-600 text-slate-100 shadow'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
              }`}
            >
              <KeyRound className="h-3 w-3" />
              <span className="hidden md:inline">Credentials</span>
            </button>
          </nav>

          <button
            id="theme-toggle"
            onClick={() => setTheme(prev => prev === 'dark' ? 'light' : 'dark')}
            className="h-8 px-2.5 flex items-center gap-1.5 rounded-lg bg-slate-950 border border-slate-800 hover:bg-slate-900 hover:border-slate-700 text-slate-400 hover:text-slate-100 transition-all cursor-pointer font-mono text-[9px] uppercase tracking-wider font-bold"
            title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}
          >
            {theme === 'dark' ? (
              <>
                <Sun className="h-3.5 w-3.5 text-amber-400 animate-pulse" />
                <span className="hidden sm:inline">Light Mode</span>
              </>
            ) : (
              <>
                <Moon className="h-3.5 w-3.5 text-blue-500" />
                <span className="hidden sm:inline">Dark Mode</span>
              </>
            )}
          </button>

          <div className="flex items-center gap-2.5 text-xs">
            <span className="status-dot text-emerald-500 bg-emerald-500"></span>
            <span className="text-[11px] font-bold text-emerald-500 uppercase tracking-wider hidden lg:inline">
              CONNECTED
            </span>
          </div>

          <div className="flex items-center gap-3 border-l border-slate-800 pl-3">
            <div className="flex flex-col text-right hidden xl:block">
              <span id="user-email-badge" className="text-[10px] font-mono text-slate-300 font-bold select-text">{userEmail}</span>
              <span className="text-[8px] font-mono text-emerald-400 uppercase font-bold tracking-widest">xyzcomp Domain</span>
            </div>
            <button
              id="logout-button"
              onClick={handleLogout}
              className="text-[10px] font-mono font-bold text-slate-400 hover:text-red-400 px-2 py-1 bg-slate-950 hover:bg-red-950/20 rounded border border-slate-800 hover:border-red-900/30 transition-all uppercase cursor-pointer"
            >
              Sign Out
            </button>
          </div>
        </div>
      </header>

      {/* Main Container Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {loading ? (
          <div className="flex flex-col items-center justify-center py-28 space-y-4">
            <RefreshCw className="h-10 w-10 text-blue-500 animate-spin" />
            <p className="text-xs font-mono text-slate-450 text-slate-400 uppercase tracking-widest animate-pulse">
              Initializing Secure MongoDB Correlation State Machine...
            </p>
          </div>
        ) : (
          <div className="space-y-6">
            
            {/* Top Metric aggregations */}
            <MetricCards 
              stats={stats} 
              rules={rules}
              useCaseFilter={useCaseFilter}
              onUseCaseFilterChange={setUseCaseFilter}
              onCardClick={handleMetricCardClick} 
            />

            {/* Dashboard and Heatmap View wrapper */}
            {activeTab === 'dashboard' && (
              <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
                
                {/* Left side Status panel + Shortcuts */}
                <div className="lg:col-span-1 space-y-4">
                  <SystemStatusCard status={systemStatus} onSync={fetchAllData} />
                  
                  {/* SIEM integration shortcuts summary */}
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow font-mono text-xs text-slate-400">
                    <h4 className="text-slate-300 font-bold mb-3 uppercase flex items-center">
                      <Terminal className="h-4 w-4 mr-1.5 text-blue-400" />
                      Platform Settings
                    </h4>
                    <p className="leading-relaxed mb-4 text-[11px]">
                      {systemStatus.platform === 'Palo Alto XSIAM'
                        ? 'The engine maps Palo Alto XSIAM XQL queries directly to MITRE identifiers. Sync updates the dynamic repository logs.'
                        : systemStatus.platform === 'Microsoft Sentinel'
                          ? 'The engine maps Microsoft Sentinel KQL queries directly to MITRE identifiers. Sync updates the dynamic repository logs.'
                          : systemStatus.platform === 'CrowdStrike Falcon'
                            ? 'The engine maps CrowdStrike Falcon RTR signatures directly to MITRE identifiers. Sync updates the dynamic repository logs.'
                            : 'The engine maps native security rule events and queries directly to MITRE identifiers. Sync updates the dynamic repository logs.'}
                    </p>
                    <button
                      onClick={() => setActiveTab('integration')}
                      className="w-full py-2 bg-slate-950 border border-slate-850 hover:bg-slate-800 text-slate-300 hover:text-slate-100 rounded-lg text-center font-bold text-[10px] uppercase transition cursor-pointer"
                    >
                      Update Platform Credentials
                    </button>
                  </div>
                </div>

                {/* Main 5x2 ATT&CK Heatmap Grid */}
                <div className="lg:col-span-3">
                  <TacticHeatmap coverage={coverage} onMitreUpdated={fetchAllData} />
                </div>

              </div>
            )}

            {/* Rule Validation Page Wrapper */}
            {activeTab === 'rules' && (
              <div className="space-y-4">
                <RuleValidationTable 
                  rules={rules} 
                  onRuleUpdated={fetchAllData} 
                  statusFilter={statusFilter}
                  onStatusFilterChange={setStatusFilter}
                  useCaseFilter={useCaseFilter}
                  onUseCaseFilterChange={setUseCaseFilter}
                />
              </div>
            )}

            {/* Configuration Credentials Tab Wrapper */}
            {activeTab === 'integration' && (
              <div className="max-w-2xl mx-auto py-4">
                <SiemIntegration onSaved={fetchAllData} />
              </div>
            )}

          </div>
        )}

      </main>

      {/* Footer Status Indicators */}
      <footer className="border-t border-slate-850 bg-slate-950 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 text-center sm:text-left flex flex-col sm:flex-row justify-between items-center gap-2 font-mono text-[10px] text-slate-500 uppercase tracking-widest">
          <span>SECURE REPOSITORY ENGINE OPERATIONAL</span>
          <span>© 14.1 SECURITY OPERATION PLATFORM CONTROLLERS</span>
        </div>
      </footer>
    </div>
  );
}
