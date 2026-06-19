import { useState } from 'react';
import { Shield, RefreshCw, Radio, Server, Cpu, Database } from 'lucide-react';
import { SystemStatus } from '../types';

interface SystemStatusCardProps {
  status: SystemStatus;
  onSync: () => void;
}

export default function SystemStatusCard({ status, onSync }: SystemStatusCardProps) {
  const [syncing, setSyncing] = useState(false);
  const [syncMessage, setSyncMessage] = useState('');

  const triggerManualSync = async () => {
    setSyncing(true);
    setSyncMessage('');
    try {
      const response = await fetch('/api/sync', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await response.json();
      if (response.ok && data.success) {
        setSyncMessage(data.message);
        onSync(); // Notify parent of database rule changes
        setTimeout(() => setSyncMessage(''), 4500);
      } else {
        setSyncMessage('Sync failed. Please verify credentials configuration.');
      }
    } catch {
      setSyncMessage('Network sync request timed out.');
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="space-y-2">
      {/* Required Text Label Above the System Status Card */}
      <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
        <span className="uppercase tracking-wider">System Architecture</span>
        <span className="text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20 text-[10px]">
          v2.4.1 LIVE
        </span>
      </div>

      {/* System Status Card Container */}
      <div 
        id="system-status-card"
        className="bg-[#151921] border border-slate-800 rounded-lg p-5 shadow-sm relative"
      >
        <div className="flex items-center justify-between mb-4 border-b border-slate-800 pb-3">
          <div className="flex items-center space-x-2">
            <div className="p-1.5 bg-blue-500/10 rounded border border-blue-500/20">
              <Shield className="h-4 w-4 text-blue-400" />
            </div>
            <h3 className="text-xs font-semibold text-slate-300 tracking-wider uppercase">
              System Health
            </h3>
          </div>
          <div className="flex items-center space-x-1.5 bg-emerald-500/10 text-emerald-400 text-[10px] font-mono px-2 py-0.5 rounded border border-emerald-500/20">
            <span className="relative flex h-1.5 w-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
            </span>
            <span>ACTIVE STATUS</span>
          </div>
        </div>

        {/* Detailed Status Grid */}
        <div className="space-y-3 font-mono text-[11px] text-slate-330">
          <div className="flex items-center justify-between py-1 border-b border-slate-800/60 text-slate-300">
            <div className="flex items-center space-x-2 text-slate-400">
              <Server className="h-3.5 w-3.5 text-slate-500" />
              <span>Platform:</span>
            </div>
            <span className="text-slate-200 font-bold">{status.platform}</span>
          </div>

          <div className="flex items-center justify-between py-1 border-b border-slate-800/60 text-slate-300">
            <div className="flex items-center space-x-2 text-slate-400">
              <Cpu className="h-3.5 w-3.5 text-slate-500" />
              <span>Rule Engine:</span>
            </div>
            <span className="text-slate-300">{status.ruleEngineVersion}</span>
          </div>

          <div className="flex flex-col space-y-1.5 py-1 border-b border-slate-800/60 text-slate-300">
            <div className="flex items-center justify-between text-slate-300">
              <div className="flex items-center space-x-2 text-slate-400">
                <Database className="h-3.5 w-3.5 text-slate-500" />
                <span>Database:</span>
              </div>
              <span className="text-blue-400 font-bold">{status.databaseStatus}</span>
            </div>
            {status.mongoDbStatus && (
              <div className="flex items-center justify-between pl-5 text-[9px] font-mono tracking-wider uppercase font-bold">
                <span className="text-slate-500">MongoDB Link:</span>
                <span className={status.mongoConnected ? "text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20" : "text-slate-400 bg-slate-800/30 px-1.5 py-0.5 rounded border border-slate-800"}>
                  {status.mongoDbStatus}
                </span>
              </div>
            )}
          </div>

          <div className="flex items-center justify-between py-1 text-slate-300">
            <div className="flex items-center space-x-2 text-slate-400">
              <Radio className="h-3.5 w-3.5 text-slate-500" />
              <span>Rules Ingest:</span>
            </div>
            <span className="text-slate-200 font-semibold">{status.ruleCount} Active Rules</span>
          </div>
        </div>

        {/* Sync trigger button */}
        <div className="mt-5">
          <button
            onClick={triggerManualSync}
            disabled={syncing}
            className={`w-full py-2 rounded font-mono uppercase tracking-wider text-[10px] font-bold border transition-all flex items-center justify-center space-x-1.5 cursor-pointer ${
              syncing 
                ? 'bg-blue-600/30 border-blue-500/20 text-blue-300 opacity-60 cursor-not-allowed'
                : 'bg-slate-950 border-slate-800 text-slate-300 hover:text-slate-100 hover:bg-slate-900'
            }`}
          >
            <RefreshCw className={`h-3 w-3 ${syncing ? 'animate-spin' : ''}`} />
            <span>{syncing ? 'Syncing...' : 'Sync SIEM Logic'}</span>
          </button>
        </div>

        {syncMessage && (
          <p className="mt-3 text-[10px] text-center font-mono text-blue-450 text-blue-400 animate-pulse bg-blue-500/10 py-1.5 px-2 border border-blue-500/20 rounded">
            {syncMessage}
          </p>
        )}
      </div>
    </div>
  );
}
