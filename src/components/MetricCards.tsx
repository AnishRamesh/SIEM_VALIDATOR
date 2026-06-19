import { Layers, CheckCircle2, AlertOctagon, HelpCircle, Compass, AlertTriangle, Sliders } from 'lucide-react';
import { DashboardStats, CorrelationRule } from '../types';

interface MetricCardsProps {
  stats: DashboardStats;
  rules?: CorrelationRule[];
  useCaseFilter: 'All' | 'UC' | 'UAT' | 'threat';
  onUseCaseFilterChange: (useCase: 'All' | 'UC' | 'UAT' | 'threat') => void;
  onCardClick?: (cardId: string) => void;
}

export default function MetricCards({ stats, rules = [], useCaseFilter, onUseCaseFilterChange, onCardClick }: MetricCardsProps) {
  const getUseCaseCount = () => {
    if (!rules || rules.length === 0) return 0;
    if (useCaseFilter === 'All') {
      return rules.length;
    }
    if (useCaseFilter === 'UC') {
      return rules.filter(r => r.ruleName && r.ruleName.trim().toUpperCase().startsWith('UC')).length;
    }
    if (useCaseFilter === 'UAT') {
      return rules.filter(r => r.ruleName && r.ruleName.trim().toUpperCase().startsWith('UAT')).length;
    }
    if (useCaseFilter === 'threat') {
      return rules.filter(r => r.ruleName && r.ruleName.trim().toLowerCase().startsWith('threat')).length;
    }
    return 0;
  };

  const items = [
    {
      id: 'metric-total-rules',
      label: 'SIEM Rules Loaded',
      value: stats.totalRules,
      subText: 'Updated live',
      icon: Layers,
      color: 'text-blue-500',
      bgColor: 'bg-blue-600/10',
      borderColor: 'border-blue-500/20',
      clickable: true
    },
    {
      id: 'metric-validated-accurate',
      label: 'Validated Accurate',
      value: stats.correctRules,
      subText: '100% Correct mapping',
      icon: CheckCircle2,
      color: 'text-emerald-500',
      bgColor: 'bg-emerald-600/10',
      borderColor: 'border-emerald-500/20',
      clickable: true
    },
    {
      id: 'metric-requires-remediation',
      label: 'Needs Remediation',
      value: stats.needsFixRules,
      subText: 'Immediate review',
      icon: AlertOctagon,
      color: 'text-rose-500',
      bgColor: 'bg-rose-600/10',
      borderColor: 'border-rose-500/20',
      clickable: true
    },
    {
      id: 'metric-unassigned-rules',
      label: 'Unassigned Queue',
      value: stats.unassignedRules,
      subText: 'Requires triage',
      icon: HelpCircle,
      color: 'text-amber-500',
      bgColor: 'bg-amber-600/10',
      borderColor: 'border-amber-500/20',
      clickable: true
    },
    {
      id: 'metric-missing-techniques',
      label: 'Missing Techniques',
      value: stats.missingTechniqueRules !== undefined ? stats.missingTechniqueRules : 0,
      subText: 'Completely unmapped',
      icon: AlertTriangle,
      color: 'text-red-500',
      bgColor: 'bg-red-600/10',
      borderColor: 'border-red-500/20',
      clickable: true
    },
    {
      id: 'metric-missing-subtechniques',
      label: 'Missing Sub-Techniques',
      value: stats.missingSubTechniqueRules !== undefined ? stats.missingSubTechniqueRules : 0,
      subText: 'Parent technique only',
      icon: AlertTriangle,
      color: 'text-amber-500',
      bgColor: 'bg-amber-600/10',
      borderColor: 'border-amber-500/20',
      clickable: true
    },
    {
      id: 'metric-use-cases',
      label: 'Use Case Category',
      value: getUseCaseCount(),
      subText: useCaseFilter === 'All' ? 'ALL SIEM Rules' : useCaseFilter === 'UC' ? 'Production (UC)' : useCaseFilter === 'UAT' ? 'Testing (UAT)' : 'Hunting (threat)',
      icon: Sliders,
      color: 'text-indigo-400',
      bgColor: 'bg-indigo-600/10',
      borderColor: 'border-indigo-500/20',
      clickable: true,
      hasDropdown: true
    },
    {
      id: 'metric-average-confidence',
      label: 'Avg Align Confidence',
      value: stats.averageConfidence === null || stats.averageConfidence === undefined
        ? 'null'
        : `${stats.averageConfidence}%`,
      subText: stats.averageConfidence === null || stats.averageConfidence === undefined
        ? 'AI Engine Offline'
        : 'Dynamic calculation',
      icon: Compass,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-600/10',
      borderColor: 'border-cyan-500/20',
      clickable: false
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 xl:grid-cols-4 2xl:grid-cols-8 gap-4">
      {items.map((card) => {
        const Icon = card.icon;
        const isClickable = card.clickable && !!onCardClick;
        return (
          <div
            key={card.id}
            id={card.id}
            onClick={() => {
              if (isClickable) {
                onCardClick(card.id);
              }
            }}
            className={`bg-[#151921] border border-slate-800 rounded-lg p-4 shadow-sm flex flex-col justify-between h-28 relative overflow-hidden transition-all ${
              isClickable 
                ? 'cursor-pointer hover:border-blue-500/40 hover:bg-[#1c222e] hover:shadow-md hover:scale-[1.01] active:scale-[0.99]' 
                : ''
            }`}
          >
            <div className="flex justify-between items-start">
              <div className="flex-1 min-w-0">
                <div className="text-[10px] font-mono text-slate-400 uppercase tracking-wider truncate">
                  {card.label}
                </div>
                <h3 className="text-2xl font-semibold font-sans text-slate-100 tracking-tight mt-1 leading-none">
                  {card.value}
                </h3>
              </div>
              <div className={`p-1.5 shrink-0 ${card.bgColor} ${card.borderColor} border rounded ml-2`}>
                <Icon className={`h-4 w-4 ${card.color}`} />
              </div>
            </div>
            {card.hasDropdown ? (
              <div className="mt-1.5 w-full" onClick={(e) => { e.stopPropagation(); }}>
                <select
                  value={useCaseFilter}
                  onChange={(e) => {
                    onUseCaseFilterChange(e.target.value as 'All' | 'UC' | 'UAT' | 'threat');
                  }}
                  className="w-full bg-[#0B0E14] border border-slate-800 text-slate-300 hover:text-slate-100 rounded px-1.5 py-0.5 text-[9px] font-mono focus:outline-none cursor-pointer select-none uppercase font-bold"
                >
                  <option value="All">ALL (SIEM)</option>
                  <option value="UC">Production (UC)</option>
                  <option value="UAT">Testing (UAT)</option>
                  <option value="threat">Hunting (threat)</option>
                </select>
              </div>
            ) : (
              <div className="flex items-center space-x-1.5 text-[10px] font-mono text-slate-500 mt-2">
                <span className={`w-1.5 h-1.5 rounded-full ${card.color.replace('text-', 'bg-')} animate-pulse`} />
                <span className="truncate">{card.subText}</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
