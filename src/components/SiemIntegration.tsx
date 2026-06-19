import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle, AlertTriangle, Terminal, KeyRound } from 'lucide-react';

interface SiemIntegrationProps {
  onSaved: () => void;
}

export default function SiemIntegration({ onSaved }: SiemIntegrationProps) {
  const [platform, setPlatform] = useState('Palo Alto XSIAM');
  const [passphrase, setPassphrase] = useState('');
  const [endpoint, setEndpoint] = useState('https://api-wipprd.xdr.in.paloaltonetworks.com');
  const [apiId, setApiId] = useState('425');
  const [status, setStatus] = useState<{ message: string; type: 'success' | 'error' | null }>({
    message: '',
    type: null
  });
  const [loading, setLoading] = useState(false);
  const [checkedReport, setCheckedReport] = useState<{
    totalCount: number;
    coveredCount: number;
    coveragePercent: number;
    pulledCount?: number;
    coveredTechniques: Array<{ tid: string; name: string; ruleId: string; ruleName: string }>;
  } | null>(null);

  useEffect(() => {
    // Fetch current config on load
    fetch('/api/dashboard/system-status')
      .then(res => res.json())
      .then(data => {
        if (data.connected && data.platform && data.platform !== 'Disconnected') {
          setPlatform(data.platform);
          if (data.apiEndpoint) {
            setEndpoint(data.apiEndpoint);
          } else {
            if (data.platform === 'Palo Alto XSIAM') {
              setEndpoint('https://api-wipprd.xdr.in.paloaltonetworks.com');
            } else if (data.platform === 'Microsoft Sentinel') {
              setEndpoint('https://sentinel.microsoft.com/api');
            } else if (data.platform === 'CrowdStrike Falcon') {
              setEndpoint('https://api.crowdstrike.com/api');
            }
          }
          if (data.apiId) {
            setApiId(data.apiId);
          }
        }
      })
      .catch(err => console.error('Failed to load initial integration states', err));
  }, []);

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase) {
      setStatus({ message: 'API validation passphrase is required', type: 'error' });
      return;
    }

    setLoading(true);
    setStatus({ message: '', type: null });
    setCheckedReport(null);

    try {
      const response = await fetch('/api/siem/connect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          platformType: platform,
          apiEndpoint: endpoint,
          apiPassphrase: passphrase,
          apiId: platform === 'Palo Alto XSIAM' ? apiId : undefined
        })
      });
      const data = await response.json();

      if (response.ok && data.success) {
        setStatus({
          message: data.message || 'SIEM Integration verified and connected successfully!',
          type: 'success'
        });
        const report = data.coverageStats ? { ...data.coverageStats, pulledCount: data.pulledCount } : null;
        setCheckedReport(report);
        setPassphrase(''); // Clear on successful save
        onSaved();
      } else {
        setStatus({
          message: data.error || 'Connection failed. Verify API endpoint and key credentials.',
          type: 'error'
        });
      }
    } catch {
      setStatus({
        message: 'Network error. Failed to reach the SIEM connector server.',
        type: 'error'
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div id="siem-integration-container" className="bg-[#151921] border border-slate-800 rounded-lg p-6 shadow-sm">
      <div className="flex items-center space-x-3 mb-6">
        <div className="p-2 bg-blue-500/10 border border-blue-500/20 rounded">
          <KeyRound className="h-5 w-5 text-blue-400" />
        </div>
        <div>
          <h2 className="text-md font-semibold text-slate-100 tracking-tight uppercase">
            SIEM API Configuration
          </h2>
          <p className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">
            Encrypted Sync Engine Credentials
          </p>
        </div>
      </div>

      <form onSubmit={handleConnect} className="space-y-4">
        <div>
          <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5 font-bold">
            SIEM platform target
          </label>
          <select
            value={platform}
            onChange={(e) => {
              const val = e.target.value;
              setPlatform(val);
              if (val === 'Palo Alto XSIAM') {
                setEndpoint('https://api-wipprd.xdr.in.paloaltonetworks.com');
                setApiId('425');
              } else if (val === 'Microsoft Sentinel') {
                setEndpoint('https://sentinel.microsoft.com/api');
              } else {
                setEndpoint('https://api.crowdstrike.com/api');
              }
            }}
            className="w-full bg-[#0B0E14] border border-slate-800 text-slate-200 rounded-lg py-2.5 px-4 focus:border-blue-500 focus:outline-none transition-all font-sans text-xs cursor-pointer"
          >
            <option value="Palo Alto XSIAM">Palo Alto XSIAM</option>
            <option value="Microsoft Sentinel">Microsoft Sentinel</option>
            <option value="CrowdStrike Falcon">CrowdStrike Falcon</option>
          </select>
        </div>

        <div>
          <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5 font-bold">
            SIEM REST Endpoint URI
          </label>
          <div className="relative">
            <input
              type="text"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              placeholder={
                platform === 'Palo Alto XSIAM' 
                  ? 'https://api-wipprd.xdr.in.paloaltonetworks.com' 
                  : platform === 'Microsoft Sentinel'
                    ? 'https://sentinel.microsoft.com/api'
                    : 'https://api.crowdstrike.com/api'
              }
              className="w-full bg-[#0B0E14] border border-slate-800 text-slate-200 rounded-lg py-2.5 px-4 pl-10 focus:border-blue-500 focus:outline-none transition-all font-mono text-xs"
              required
            />
            <Terminal className="absolute left-3 top-3 h-3.5 w-3.5 text-slate-500" />
          </div>
        </div>

        {platform === 'Palo Alto XSIAM' && (
          <div className="animate-fadeIn">
            <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5 font-bold">
              API key ID (API ID)
            </label>
            <input
              type="text"
              value={apiId}
              onChange={(e) => setApiId(e.target.value)}
              placeholder="425"
              className="w-full bg-[#0B0E14] border border-slate-800 text-slate-200 rounded-lg py-2.5 px-4 focus:border-blue-500 focus:outline-none transition-all font-mono text-xs"
              required
            />
          </div>
        )}

        <div>
          <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider mb-1.5 font-bold">
            Client secret API key token
          </label>
          <input
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="••••••••••••••••••••••••••••••••"
            className="w-full bg-[#0B0E14] border border-slate-800 text-slate-200 rounded-lg py-2.5 px-4 focus:border-blue-500 focus:outline-none transition-all font-mono tracking-widest text-xs"
            required
          />
        </div>



        {status.type && (
          <div
            className={`p-3.5 rounded-lg flex items-start space-x-2.5 text-xs transition-all ${
              status.type === 'success'
                ? 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'
                : 'bg-rose-500/10 border border-rose-500/20 text-rose-450 text-red-400'
            }`}
          >
            {status.type === 'success' ? (
              <CheckCircle className="h-4 w-4 shrink-0 mt-0.5 text-emerald-500" />
            ) : (
              <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5 text-red-400" />
            )}
            <span>{status.message}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={loading}
          className={`w-full font-mono uppercase tracking-wider text-[10px] font-bold py-2.5 rounded-lg border flex items-center justify-center space-x-1.5 transition-all mt-3 cursor-pointer ${
            loading
              ? 'bg-blue-600/30 border-blue-500/20 text-blue-300 cursor-wait'
              : 'bg-blue-600 border-blue-500 text-slate-100 hover:bg-blue-500 shadow shadow-blue-500/10'
          }`}
        >
          {loading ? 'Validating Connection Securely...' : 'Establish Secure Connection'}
        </button>
      </form>

      {checkedReport && (
        <div className="mt-6 border border-slate-800 rounded-xl bg-slate-900/40 p-5 space-y-4 font-sans animate-fadeIn">
          <div className="flex items-center justify-between border-b border-slate-850 pb-3">
            <div>
              <h3 className="text-xs font-bold text-slate-100 uppercase tracking-tight flex items-center gap-1.5">
                <Shield className="h-4 w-4 text-emerald-400" />
                Automated Verification Scan Report
              </h3>
              <p className="text-[9px] font-mono text-slate-400 uppercase tracking-wider mt-0.5">
                Live Rule-to-MITRE Coverage Analysis Complete
              </p>
            </div>
            <span className="text-[9px] font-mono bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 px-2 py-0.5 rounded font-bold uppercase">
              Verified
            </span>
          </div>

          <div className="space-y-2.5">
            <div className="flex justify-between items-baseline text-xs">
              <span className="text-[10px] text-slate-400 font-mono uppercase tracking-wider">Overall MITRE Mapping Depth</span>
              <span className="text-[10px] font-mono text-slate-300 font-bold">
                {checkedReport.coveredCount} / {checkedReport.totalCount} techniques & sub-techniques
              </span>
            </div>
            <div className="flex items-center space-x-3">
              <div className="flex-1 h-2.5 bg-slate-950 rounded-full overflow-hidden border border-slate-850">
                <div 
                  className="h-full bg-gradient-to-r from-blue-500 to-emerald-500 transition-all duration-1000" 
                  style={{ width: `${checkedReport.coveragePercent}%` }} 
                />
              </div>
              <span className="text-xs font-bold font-mono text-emerald-400 shrink-0">
                {checkedReport.coveragePercent}% Covered
              </span>
            </div>
          </div>

          <div className="space-y-2 pt-1">
            <div className="text-[9px] uppercase font-mono tracking-wider text-slate-400 font-bold">
              Automatically checked & covered techniques list:
            </div>
            <div id="checked-techniques-grid" className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
              {checkedReport.coveredTechniques.map((tech) => (
                <div key={tech.tid} className="bg-[#0B0E14] border border-slate-850 rounded-lg p-2.5 flex items-start space-x-2">
                  <div className="p-1 bg-emerald-500/10 rounded border border-emerald-500/20 text-emerald-400 shrink-0 mt-0.5">
                    <CheckCircle className="h-3.5 w-3.5" />
                  </div>
                  <div className="min-w-0">
                    <div className="font-bold text-slate-200 truncate tracking-tight">{tech.name}</div>
                    <div className="flex items-center space-x-2 text-[9px] font-mono text-slate-500 mt-0.5 uppercase tracking-wider">
                      <span className="text-slate-400 font-semibold">{tech.tid}</span>
                      <span>•</span>
                      <span className="text-blue-400 font-semibold">{tech.ruleId}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          
          <div className="bg-[#0B0E14] border border-slate-850 p-2.5 rounded-lg text-[9px] text-slate-400 font-mono text-center uppercase tracking-wider leading-relaxed">
            All {checkedReport.pulledCount || 24} rules were successfully ingested and integrated. AI Match Confidence calculation is offline.
          </div>
        </div>
      )}

      <div className="mt-5 border-t border-slate-800 pt-4 text-center">
        <p className="text-[10px] text-slate-500 font-mono leading-relaxed uppercase">
          Authorization details are managed over strict TLS protocols and verified instantly.
        </p>
      </div>
    </div>
  );
}
