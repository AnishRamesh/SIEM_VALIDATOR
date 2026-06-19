import { useState, useEffect } from 'react';
import { ArrowUpRight, ShieldCheck, ShieldAlert, AlertCircle, RefreshCw, X, FileText, Download, Search, FileDown } from 'lucide-react';
import { TacticCoverage, TacticDetailResponse } from '../types';
import { jsPDF } from 'jspdf';

interface TacticHeatmapProps {
  coverage: TacticCoverage[];
  onMitreUpdated: () => void;
}

export default function TacticHeatmap({ coverage, onMitreUpdated }: TacticHeatmapProps) {
  const [updatingMitre, setUpdatingMitre] = useState(false);
  const [mitreMessage, setMitreMessage] = useState('');
  
  // Drilldown technique drill modal / panel details
  const [selectedTactic, setSelectedTactic] = useState<TacticCoverage | null>(null);
  const [tacticDetails, setTacticDetails] = useState<TacticDetailResponse | null>(null);
  const [loadingDetails, setLoadingDetails] = useState(false);
  const [filterType, setFilterType] = useState<'ALL' | 'COVERED' | 'UNCOVERED'>('ALL');

  // Uncovered global report modal details
  const [showReportModal, setShowReportModal] = useState(false);
  const [reportData, setReportData] = useState<any[] | null>(null);
  const [loadingReport, setLoadingReport] = useState(false);
  const [reportSearch, setReportSearch] = useState('');

  // Fetch Uncovered Report
  useEffect(() => {
    if (!showReportModal) return;
    setLoadingReport(true);
    fetch('/api/heatmap/uncovered-report')
      .then(res => res.json())
      .then(data => {
        setReportData(data);
      })
      .catch(err => console.error('Failed to retrieve uncovered report', err))
      .finally(() => setLoadingReport(false));
  }, [showReportModal, coverage]);

  const exportAsPdf = () => {
    if (!reportData) return;
    const doc = new jsPDF();
    
    // Set up standard elegant typography
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(26, 32, 44); // Slate 800
    doc.text("MITRE ATT&CK UNCOVERED GAP REPORT", 14, 20);
    
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(113, 128, 150); // Slate 500
    doc.text(`Corporate SIEM Coverage Analysis | Generated: ${new Date().toLocaleString()}`, 14, 26);
    
    doc.setDrawColor(226, 232, 240); // Slate 200
    doc.line(14, 30, 196, 30);
    
    let totalParentUncovered = 0;
    let totalSubUncovered = 0;
    reportData.forEach(t => {
      t.techniques.forEach((tech: any) => {
        if (!tech.covered) totalParentUncovered++;
        totalSubUncovered += tech.uncoveredSubTechniques?.length || 0;
      });
    });
    
    // Summary Metrics Banner card structure
    doc.setFillColor(248, 250, 252); // Soft background (slate 50)
    doc.rect(14, 34, 182, 28, "F");
    
    doc.setFont("helvetica", "bold");
    doc.setFontSize(10);
    doc.setTextColor(51, 65, 85); // Slate 700
    doc.text("SUMMARY METRICS / RISK HIGHLIGHTS", 20, 41);
    
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(100, 116, 139); // Slate 500
    doc.text(`• Total Tactics with Coverage Gaps: ${reportData.length}`, 20, 47);
    doc.text(`• Uncovered Parent Techniques: ${totalParentUncovered}`, 20, 52);
    doc.text(`• Uncovered Sub-Techniques: ${totalSubUncovered}`, 20, 57);
    
    let y = 70;
    const pageHeight = doc.internal.pageSize.height;
    
    reportData.forEach(tactic => {
      if (y > pageHeight - 30) {
        doc.addPage();
        y = 20;
      }
      
      doc.setFont("helvetica", "bold");
      doc.setFontSize(11);
      doc.setTextColor(30, 41, 59); // Slate 900
      doc.text(`Tactic [${tactic.tacticId}] - ${tactic.name.toUpperCase()}`, 14, y);
      y += 5;
      
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8.5);
      doc.setTextColor(148, 163, 184); // Slate 400
      doc.text(`Uncovered techniques: ${tactic.uncoveredCount}`, 14, y);
      y += 5;
       
      doc.setDrawColor(241, 245, 249); // slate 100
      doc.line(14, y, 196, y);
      y += 5;
      
      tactic.techniques.forEach((tech: any) => {
        if (y > pageHeight - 20) {
          doc.addPage();
          y = 20;
        }
        
        const parentStatus = tech.covered ? "Covered" : "Uncovered";
        doc.setFont("helvetica", "bold");
        doc.setFontSize(9);
        doc.setTextColor(71, 85, 105); // Slate 600
        doc.text(`• [${tech.tid}] ${tech.name}`, 18, y);
        
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8.5);
        if (tech.covered) {
          doc.setTextColor(22, 163, 74); // Green 600
        } else {
          doc.setTextColor(225, 29, 72); // Rose 600
        }
        doc.text(`(${parentStatus})`, 160, y);
        y += 4.5;
        
        if (tech.uncoveredSubTechniques && tech.uncoveredSubTechniques.length > 0) {
          doc.setFont("helvetica", "normal");
          doc.setFontSize(8);
          doc.setTextColor(148, 163, 184);
          doc.text("Uncovered Sub-techniques:", 24, y);
          y += 4;
          
          tech.uncoveredSubTechniques.forEach((sub: any) => {
            if (y > pageHeight - 15) {
              doc.addPage();
              y = 20;
            }
            doc.setFont("helvetica", "normal");
            doc.setFontSize(8);
            doc.setTextColor(100, 116, 139); // Slate 500
            doc.text(`  - [${sub.tid}] ${sub.name}`, 26, y);
            y += 4;
          });
        }
        y += 2;
      });
      y += 5;
    });
    
    doc.save("uncovered_mitre_attack_report.pdf");
  };

  const exportAsCsv = () => {
    if (!reportData) return;
    const header = ['Tactic ID', 'Tactic Name', 'Technique ID', 'Technique Name', 'Status', 'Uncovered Sub-Techniques'];
    const rows: string[][] = [];
    
    reportData.forEach(tactic => {
      tactic.techniques.forEach((tech: any) => {
        const parentStatus = tech.covered ? "Covered" : "Uncovered";
        const subTechList = (tech.uncoveredSubTechniques || []).map((s: any) => `${s.tid}: ${s.name}`).join('; ');
        rows.push([
          tactic.tacticId,
          `"${tactic.name.replace(/"/g, '""')}"`,
          tech.tid,
          `"${tech.name.replace(/"/g, '""')}"`,
          parentStatus,
          `"${subTechList.replace(/"/g, '""')}"`
        ]);
      });
    });
    
    const csvContent = "data:text/csv;charset=utf-8,\uFEFF" 
      + [header.join(','), ...rows.map(e => e.join(','))].join('\n');
    
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.href = encodedUri;
    link.download = "uncovered_mitre_attack_report.csv";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const getFilteredReport = () => {
    if (!reportData) return [];
    if (!reportSearch) return reportData;

    const term = reportSearch.toLowerCase();
    return reportData.map(tactic => {
      if (tactic.name.toLowerCase().includes(term) || tactic.tacticId.toLowerCase().includes(term)) {
        return tactic;
      }

      const subFiltered = tactic.techniques.filter((tech: any) => {
        const parentMatch = tech.tid.toLowerCase().includes(term) || tech.name.toLowerCase().includes(term);
        const subMatch = tech.uncoveredSubTechniques?.some((sub: any) => 
          sub.tid.toLowerCase().includes(term) || sub.name.toLowerCase().includes(term)
        );
        return parentMatch || subMatch;
      });

      if (subFiltered.length > 0) {
        return {
          ...tactic,
          techniques: subFiltered,
          uncoveredCount: subFiltered.length
        };
      }
      return null;
    }).filter(t => t !== null) as any[];
  };

  const getReportSummaryCounts = () => {
    if (!reportData) return { tactics: 0, parents: 0, subs: 0 };
    let tactics = reportData.length;
    let parents = 0;
    let subs = 0;
    reportData.forEach(t => {
      t.techniques.forEach((tech: any) => {
        if (!tech.covered) parents++;
        if (tech.uncoveredSubTechniques) {
          subs += tech.uncoveredSubTechniques.length;
        }
      });
    });
    return { tactics, parents, subs };
  };

  // Load detailed techniques drilldown on selection
  useEffect(() => {
    if (!selectedTactic) {
      setTacticDetails(null);
      return;
    }
    setFilterType('ALL');

    setLoadingDetails(true);
    fetch(`/api/tactic/${selectedTactic.tacticId}/techniques`)
      .then(res => res.json())
      .then(data => {
        setTacticDetails(data);
      })
      .catch(err => console.error('Failed to load tactic details', err))
      .finally(() => setLoadingDetails(false));
  }, [selectedTactic, coverage]); // Reload if coverage gets updated

  // Filter techniques and their sub-techniques based on the selected filterType
  const getFilteredTechniques = () => {
    if (!tacticDetails) return [];
    
    if (filterType === 'ALL') {
      return tacticDetails.techniques;
    }
    
    if (filterType === 'COVERED') {
      return tacticDetails.techniques
        .filter(tech => tech.covered)
        .map(tech => ({
          ...tech,
          subTechniques: tech.subTechniques?.filter(sub => sub.covered) || []
        }));
    }
    
    if (filterType === 'UNCOVERED') {
      return tacticDetails.techniques
        .filter(tech => !tech.covered || (tech.subTechniques && tech.subTechniques.some(sub => !sub.covered)))
        .map(tech => ({
          ...tech,
          subTechniques: tech.subTechniques?.filter(sub => !sub.covered) || []
        }))
        .filter(tech => {
          if (!tech.covered) return true;
          return tech.subTechniques && tech.subTechniques.length > 0;
        });
    }
    
    return tacticDetails.techniques;
  };

  const handleUpdateMitre = async () => {
    setUpdatingMitre(true);
    setMitreMessage('');
    try {
      const response = await fetch('/api/mitre/update', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      const data = await response.json();
      if (response.ok && data.success) {
        setMitreMessage(data.message);
        onMitreUpdated(); // Reload heatmap percentages
        setTimeout(() => setMitreMessage(''), 4500);
      } else {
        setMitreMessage('Failed to trigger update schema.');
      }
    } catch {
      setMitreMessage('Update request timed out.');
    } finally {
      setUpdatingMitre(false);
    }
  };

  // Determine heatmap node background based on percentage
  const getCoverageStyle = (percent: number) => {
    if (percent > 60) {
      return {
        bgClass: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400 hover:border-emerald-400',
        dotColor: 'bg-emerald-500'
      };
    }
    if (percent >= 40) {
      return {
        bgClass: 'bg-amber-500/10 border-amber-500/30 text-amber-400 hover:border-amber-400',
        dotColor: 'bg-amber-500'
      };
    }
    return {
      bgClass: 'bg-rose-500/10 border-rose-500/30 text-rose-400 hover:border-rose-450',
      dotColor: 'bg-rose-500'
    };
  };

  // Custom visual SVG chart calculation
  const buildSvgBarChartData = () => {
    const margin = { top: 20, right: 20, bottom: 85, left: 40 };
    const svgWidth = 800;
    const svgHeight = 285;
    const chartWidth = svgWidth - margin.left - margin.right;
    const chartHeight = svgHeight - margin.top - margin.bottom;

    const barWidth = coverage.length > 10 ? 14 : 24;
    const spacing = (chartWidth / Math.max(1, coverage.length)) - (barWidth * 1.8);

    return {
      svgWidth,
      svgHeight,
      chartHeight,
      chartWidth,
      margin,
      barWidth,
      spacing
    };
  };

  const chartParams = buildSvgBarChartData();

  return (
    <div className="space-y-6">
      {/* Tactic Coverage Heatmap Main Panel */}
      <div className="bg-[#151921] border border-slate-800 rounded-lg p-6 shadow-sm relative">
        
        {/* Header Replicated */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center gap-4 mb-5 border-b border-slate-800 pb-4">
          <div>
            <h2 className="text-md font-semibold text-slate-100 tracking-tight uppercase">
              Tactic Coverage Heatmap
            </h2>
            <p className="text-[10px] text-slate-400 font-mono mt-0.5 uppercase tracking-wider">
              SIEM Rule Mapping Compliance Analytics
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-mono text-[10px] text-slate-400 font-bold bg-slate-950 px-2.5 py-1.5 border border-slate-850 rounded">
              ATT&CK V19.1
            </span>
            <button
              id="generate-uncovered-report"
              onClick={() => setShowReportModal(true)}
              className="bg-blue-600 hover:bg-blue-500 text-white font-mono text-[10px] uppercase tracking-wider px-3 py-1.5 rounded font-extrabold flex items-center space-x-1 transition-all cursor-pointer border-none shadow shadow-blue-500/20"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>Report</span>
            </button>
            <button
              onClick={handleUpdateMitre}
              disabled={updatingMitre}
              className="bg-slate-950 border border-slate-800 text-slate-350 hover:text-slate-100 hover:bg-slate-900 font-mono text-[10px] uppercase tracking-wider px-3 py-1.5 rounded font-bold flex items-center space-x-1 transition-all cursor-pointer"
            >
              <RefreshCw className={`h-3 w-3 ${updatingMitre ? 'animate-spin' : ''}`} />
              <span>{updatingMitre ? 'Updating...' : 'Update MITRE'}</span>
            </button>
          </div>
        </div>

        {mitreMessage && (
          <div className="mb-4 py-2 px-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 font-mono text-xs rounded flex justify-between items-center">
            <span>{mitreMessage}</span>
            <button onClick={() => setMitreMessage('')} className="text-slate-400 hover:text-slate-100">
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        )}

        <p className="text-xs text-slate-400 leading-relaxed mb-5">
          Select target tactic block below to analyze security coverage, review covered sub-techniques, and see which critical vectors remain uncovered.
        </p>

        {/* Heatmap 5x2 Grid */}
        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
          {coverage.map((tactic) => {
            const isSelected = selectedTactic?.tacticId === tactic.tacticId;
            const styleDetails = getCoverageStyle(tactic.currentMonth);
            return (
              <div
                key={tactic.tacticId}
                onClick={() => setSelectedTactic(tactic)}
                className={`border rounded-lg p-3.5 cursor-pointer transition-all flex flex-col justify-between h-24 relative overflow-hidden group ${styleDetails.bgClass} ${isSelected ? 'ring-2 ring-blue-500 !bg-slate-950' : ''}`}
              >
                <div className="flex justify-between items-start">
                  <span className="font-mono font-bold text-[9px] uppercase tracking-wider text-slate-300">
                    {tactic.shortName}
                  </span>
                  <ArrowUpRight className="h-3.5 w-3.5 opacity-25 group-hover:opacity-100 transition-opacity" />
                </div>
                
                <div>
                  <h4 className="text-[11px] font-medium text-slate-200 tracking-tight mb-1 truncate">
                    {tactic.name}
                  </h4>
                  <div className="flex items-baseline space-x-1">
                    <span className="text-xl font-bold font-mono tracking-tight leading-none text-slate-100">
                      {tactic.currentMonth}%
                    </span>
                    <span className="text-[9px] text-slate-500 uppercase font-mono">mapped</span>
                  </div>
                </div>

                {/* Progress bar line back in metric cards */}
                <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-950/40">
                  <div 
                    className={`h-full ${
                      tactic.currentMonth > 60 
                        ? 'bg-emerald-500' 
                        : tactic.currentMonth >= 40 
                        ? 'bg-amber-500' 
                        : 'bg-rose-500'
                    }`} 
                    style={{ width: `${tactic.currentMonth}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {/* Legend representation at bottom */}
        <div id="coverage-legend" className="flex items-center justify-between mt-5 bg-[#0B0E14] p-3 rounded border border-slate-800 text-[10px] font-mono text-slate-500 uppercase tracking-widest">
          <span className="flex items-center">
            <span className="inline-block h-2 w-2 bg-rose-500 rounded-full mr-2" />
            Critical (&lt; 40%)
          </span>
          <span className="flex items-center">
            <span className="inline-block h-2 w-2 bg-amber-500 rounded-full mr-2" />
            Moderate (40% - 60%)
          </span>
          <span className="flex items-center">
            <span className="inline-block h-2 w-2 bg-emerald-500 rounded-full mr-2" />
            Optimized (&gt; 60%)
          </span>
        </div>
      </div>

      {/* Monthly Comparison Bar Chart */}
      <div className="bg-[#151921] border border-slate-800 rounded-lg p-6 shadow-sm">
        <div className="mb-5 border-b border-slate-850 pb-3">
          <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
            Coverage Trend Over Time
          </h3>
          <p className="text-[10px] text-slate-400 font-mono mt-0.5 uppercase tracking-wider">
            Current Calculations vs Previous Month Database Snaps
          </p>
        </div>

        {/* SVG Driven Bar Chart */}
        <div className="relative overflow-x-auto pt-2">
          <svg
            viewBox={`0 0 ${chartParams.svgWidth} ${chartParams.svgHeight}`}
            className="w-full text-slate-400 font-mono min-w-[700px] h-60"
          >
            {/* Grid Lines */}
            {[0, 25, 50, 75, 100].map((yVal) => {
              const yPos = chartParams.margin.top + (chartParams.chartHeight * (1 - yVal / 100));
              return (
                <g key={yVal}>
                  <line
                    x1={chartParams.margin.left}
                    y1={yPos}
                    x2={chartParams.svgWidth - chartParams.margin.right}
                    y2={yPos}
                    stroke="#232936"
                    strokeWidth="1"
                    strokeDasharray="3 3"
                  />
                  <text
                    x={chartParams.margin.left - 10}
                    y={yPos + 3}
                    textAnchor="end"
                    className="text-[9px] fill-slate-500"
                  >
                    {yVal}%
                  </text>
                </g>
              );
            })}

            {/* Drawing Bars */}
            {coverage.map((tactic, i) => {
              const xPos = chartParams.margin.left + (i * (chartParams.chartWidth / coverage.length)) + (coverage.length > 10 ? 8 : 12);

              // Heights relative to 100%
              const currentHeight = (tactic.currentMonth / 100) * chartParams.chartHeight;
              const prevHeight = (tactic.previousMonth / 100) * chartParams.chartHeight;

              const currentY = chartParams.margin.top + chartParams.chartHeight - currentHeight;
              const prevY = chartParams.margin.top + chartParams.chartHeight - prevHeight;

              return (
                <g key={tactic.tacticId} className="group cursor-help">
                  <title>
                    {tactic.name} - This Month: {tactic.currentMonth}%, Prev Month: {tactic.previousMonth}%
                  </title>
                  {/* Previous Month Bar (bright sky blue) */}
                  <rect
                    x={xPos}
                    y={prevY}
                    width={chartParams.barWidth}
                    height={prevHeight}
                    fill="#38BDF8"
                    className="transition-all hover:fill-sky-300"
                    rx="1.5"
                  />
                  {/* This Month Bar (glow blue/teal depending on rating) */}
                  <rect
                    x={xPos + chartParams.barWidth + 4}
                    y={currentY}
                    width={chartParams.barWidth}
                    height={currentHeight}
                    fill={tactic.currentMonth > 60 ? '#10B981' : tactic.currentMonth >= 40 ? '#F59E0B' : '#EF4444'}
                    className="transition-all opacity-80 group-hover:opacity-100"
                    rx="1.5"
                  />

                  {/* Top percent values on hover */}
                  <text
                    x={xPos + chartParams.barWidth + 2}
                    y={currentY - 6}
                    textAnchor="middle"
                    className="text-[9px] font-bold fill-slate-200 opacity-0 group-hover:opacity-100 transition-opacity"
                  >
                    {tactic.currentMonth}%
                  </text>

                  {/* Tactic Name label rotated and properly spaced */}
                  <text
                    x={xPos + chartParams.barWidth + 2}
                    y={chartParams.svgHeight - 75}
                    transform={`rotate(-35, ${xPos + chartParams.barWidth + 2}, ${chartParams.svgHeight - 75})`}
                    textAnchor="end"
                    className="text-[8.5px] font-mono font-semibold fill-slate-400 group-hover:fill-slate-200 uppercase tracking-tight"
                  >
                    {tactic.shortName}
                  </text>
                </g>
              );
            })}

            {/* Baseline bottom axis border */}
            <line
              x1={chartParams.margin.left}
              y1={chartParams.margin.top + chartParams.chartHeight}
              x2={chartParams.svgWidth - chartParams.margin.right}
              y2={chartParams.margin.top + chartParams.chartHeight}
              stroke="#232936"
              strokeWidth="1.5"
            />
          </svg>
        </div>

        {/* Legend descriptors */}
        <div className="flex items-center space-x-6 text-[10px] font-mono text-slate-500 mt-2 px-2 uppercase tracking-wider">
          <div className="flex items-center space-x-1.5">
            <span className="inline-block h-2 w-4 bg-[#38BDF8] rounded" />
            <span>PREVIOUS MONTH SNAP</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="inline-block h-2 w-4 bg-[#3B82F6] rounded" />
            <span>ACTIVE SECURITY MEASURABLES</span>
          </div>
        </div>
      </div>

      {/* Drilldown modal showing covered / uncovered techniques */}
      {selectedTactic && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[#151921] border border-slate-800 rounded-lg w-full max-w-xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
            
            {/* Header */}
            <div className="p-4 border-b border-slate-800 bg-[#0F131A] flex justify-between items-center shrink-0">
              <div>
                <span className="text-[9px] font-mono text-slate-400 tracking-widest uppercase block mb-0.5">
                  Tactic Uncovered Analysis
                </span>
                <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                  {selectedTactic.name}
                  <span className="text-[10px] bg-slate-950 text-slate-400 font-mono px-2 py-0.5 rounded border border-slate-800">
                    ID: {selectedTactic.tacticId}
                  </span>
                </h3>
              </div>
              <button
                onClick={() => setSelectedTactic(null)}
                className="text-slate-400 hover:text-slate-100 p-1 hover:bg-slate-800 rounded transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Content body */}
            <div className="p-5 overflow-y-auto space-y-5 flex-1">
              {loadingDetails ? (
                <div className="py-12 text-center text-slate-400 font-mono text-[11px] uppercase tracking-widest animate-pulse">
                  Querying database parameters...
                </div>
              ) : tacticDetails ? (
                <>
                  {/* Stats summary boxes */}
                  <div className="grid grid-cols-3 gap-3 font-mono text-[11px]">
                    <button
                      type="button"
                      onClick={() => setFilterType('ALL')}
                      className={`p-2.5 rounded text-center transition-all cursor-pointer border outline-none ${
                        filterType === 'ALL'
                          ? 'bg-slate-900 border-slate-600 text-slate-100 ring-1 ring-slate-700/50 shadow'
                          : 'bg-[#0F131A] border-slate-850 text-slate-400 hover:border-slate-800 hover:bg-slate-900/50'
                      }`}
                    >
                      <span className="text-[9px] text-slate-500 uppercase block mb-0.5">Total</span>
                      <span className="text-base font-bold text-slate-300">{tacticDetails.totalCount}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setFilterType('COVERED')}
                      className={`p-2.5 rounded text-center transition-all cursor-pointer border outline-none ${
                        filterType === 'COVERED'
                          ? 'bg-emerald-500/10 border-emerald-500 text-emerald-400 shadow shadow-emerald-500/10'
                          : 'bg-emerald-500/5 border-emerald-500/10 text-emerald-400 hover:bg-emerald-500/10 hover:border-emerald-500/20'
                      }`}
                    >
                      <span className="text-[9px] text-emerald-400 uppercase block mb-0.5">Covered</span>
                      <span className="text-base font-bold text-emerald-400">{tacticDetails.coveredCount}</span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setFilterType('UNCOVERED')}
                      className={`p-2.5 rounded text-center transition-all cursor-pointer border outline-none ${
                        filterType === 'UNCOVERED'
                          ? 'bg-rose-500/10 border-rose-500 text-rose-400 shadow shadow-rose-500/10'
                          : 'bg-rose-500/5 border-rose-500/10 text-rose-400 hover:bg-rose-500/10 hover:border-rose-500/20'
                      }`}
                    >
                      <span className="text-[9px] text-rose-400 uppercase block mb-0.5">UNCOVERED</span>
                      <span className="text-base font-bold text-rose-400">{tacticDetails.uncoveredCount}</span>
                    </button>
                  </div>

                  {/* Techniques & Sub-techniques Registry */}
                  <div className="space-y-4">
                    <h4 className="text-[10px] font-mono uppercase text-blue-500 flex items-center justify-between font-bold tracking-wider border-b border-slate-800 pb-1.5">
                      <span className="flex items-center">
                        <ShieldCheck className="h-4 w-4 mr-1.5 text-blue-400" />
                        Techniques & Sub-techniques Registry (v19.1)
                      </span>
                      <span className="text-[9px] font-mono font-bold px-2 py-0.5 rounded border border-blue-500/20 bg-blue-500/5 text-blue-400 shrink-0 uppercase tracking-widest">
                        SHOWING: {filterType === 'ALL' ? 'ALL' : filterType === 'COVERED' ? 'COVERED' : 'UNCOVERED'}
                      </span>
                    </h4>

                    <div className="space-y-3">
                      {getFilteredTechniques().length > 0 ? (
                        getFilteredTechniques().map((tech) => (
                          <div key={tech.tid} className="bg-slate-900/40 border border-slate-800 p-3.5 rounded-lg space-y-3">
                            
                            {/* Parent Technique Header */}
                            <div className="flex justify-between items-start gap-4">
                              <div className="flex items-center gap-2">
                                <span className="font-mono text-[10px] text-blue-400 font-bold bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20 shadow-sm shrink-0">
                                  {tech.tid}
                                </span>
                                <h5 className="text-xs font-semibold text-slate-100 leading-tight">
                                  {tech.name}
                                </h5>
                              </div>
                              <span className={`text-[9px] font-mono font-bold px-2 py-0.5 rounded border uppercase shrink-0 ${
                                tech.covered 
                                  ? 'bg-emerald-500/15 border-emerald-500/20 text-emerald-400' 
                                  : 'bg-rose-500/15 border-rose-500/20 text-rose-405 text-rose-400'
                              }`}>
                                {tech.covered ? 'COVERED' : 'UNCOVERED'}
                              </span>
                            </div>

                            {/* Directly Supported Rules for Parent Technique */}
                            {tech.rulesMapped && tech.rulesMapped.length > 0 && (
                              <div className="bg-slate-950/40 border border-slate-850 p-2.5 rounded text-[10px] font-mono text-slate-400 space-y-1">
                                <span className="text-[8px] text-slate-500 uppercase font-bold tracking-wider block">
                                  Directly Supporting SIEM Rules:
                                </span>
                                {tech.rulesMapped.map((rule, idx) => (
                                  <div key={idx} className="flex items-center gap-1.5">
                                    <span className="text-emerald-400 font-bold">✓</span>
                                    <span className="truncate">{rule}</span>
                                  </div>
                                ))}
                              </div>
                            )}

                            {/* Sub-techniques list */}
                            {tech.subTechniques && tech.subTechniques.length > 0 ? (
                              <div className="pl-3 border-l-2 border-slate-800 space-y-2 mt-2">
                                <span className="text-[8px] font-mono text-slate-500 uppercase tracking-widest block font-bold">
                                  Sub-techniques ({tech.subTechniques.length})
                                </span>
                                <div className="grid grid-cols-1 gap-1.5">
                                  {tech.subTechniques.map((sub) => (
                                    <div 
                                      key={sub.tid} 
                                      className="bg-slate-950/60 border border-slate-850 p-2 rounded flex flex-col sm:flex-row sm:items-center justify-between gap-2 hover:border-slate-800 transition"
                                    >
                                      <div className="space-y-1">
                                        <div className="flex items-center gap-2">
                                          <span className="font-mono text-[9px] text-cyan-400 font-semibold bg-cyan-500/15 px-1.5 py-0.2 rounded border border-cyan-500/20">
                                            {sub.tid}
                                          </span>
                                          <span className="text-[11px] font-medium text-slate-300">
                                            {sub.name}
                                          </span>
                                        </div>
                                        
                                        {sub.rulesMapped && sub.rulesMapped.length > 0 && (
                                          <div className="flex flex-wrap gap-1 mt-1">
                                            {sub.rulesMapped.map((rule, idx) => (
                                              <span 
                                                key={idx} 
                                                className="inline-flex items-center gap-1 text-[8px] font-mono text-slate-400 bg-slate-900 border border-slate-800 px-1.5 py-0.2 rounded max-w-[220px]"
                                              >
                                                <span className="text-emerald-400">✓</span> {rule}
                                              </span>
                                            ))}
                                          </div>
                                        )}
                                      </div>
                                      <span className={`text-[8px] font-mono font-bold px-2 py-0.2 rounded border uppercase shrink-0 w-fit self-start sm:self-auto ${
                                        sub.covered 
                                          ? 'bg-emerald-500/10 border-emerald-500/15 text-emerald-400' 
                                          : 'bg-rose-500/10 border-rose-500/15 text-rose-400'
                                      }`}>
                                        {sub.covered ? 'COVERED' : 'UNCOVERED'}
                                      </span>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            ) : (
                              <div className="hidden" />
                            )}
                          </div>
                        ))
                      ) : (
                        <div className="text-center py-10 border border-dashed border-slate-850 text-slate-500 font-mono text-[10px] rounded-xl bg-[#0F131A] uppercase tracking-widest leading-relaxed">
                          No {filterType === 'COVERED' ? 'covered' : 'uncovered'} techniques mapped inside this tactic scope.
                        </div>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-center py-6 text-slate-500 font-mono text-xs uppercase">
                  Details retrieval error
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-3 border-t border-slate-800 bg-[#0F131A] flex justify-end shrink-0">
              <button
                onClick={() => setSelectedTactic(null)}
                className="bg-slate-900 border border-slate-850 text-slate-300 hover:text-slate-100 px-4 py-1.5 rounded text-[10px] font-mono uppercase tracking-wider font-bold transition cursor-pointer"
              >
                Close View
              </button>
            </div>
            
          </div>
        </div>
      )}

      {/* Interactive Uncovered Gap Report Modal */}
      {showReportModal && (
        <div id="uncovered-report-overlay" className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 z-50 animate-fade-in">
          <div className="bg-[#151921] border border-slate-800 rounded-lg w-full max-w-2xl shadow-2xl overflow-hidden max-h-[85vh] flex flex-col">
            
            {/* Header */}
            <div className="p-4 border-b border-slate-800 bg-[#0F131A] flex justify-between items-center shrink-0">
              <div>
                <span className="text-[9px] font-mono text-slate-400 tracking-widest uppercase block mb-0.5">
                  Mitre ATT&CK GAP Metrics
                </span>
                <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2 uppercase tracking-wide">
                  Uncovered Security Gaps Report
                  <span className="text-[10px] bg-slate-950 text-slate-400 font-mono px-2 py-0.5 rounded border border-slate-800">
                    Live SIEM Sync
                  </span>
                </h3>
              </div>
              <button
                onClick={() => {
                  setShowReportModal(false);
                  setReportSearch('');
                }}
                className="text-slate-400 hover:text-slate-100 p-1 hover:bg-slate-800 rounded transition"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {/* Actions Bar & Search */}
            <div className="p-4 bg-[#0B0E14] border-b border-slate-800/60 flex flex-col sm:flex-row gap-3 sm:items-center justify-between shrink-0">
              <div className="relative flex-1">
                <div className="absolute inset-y-0 left-0 pl-2.5 flex items-center pointer-events-none text-slate-500">
                  <Search className="h-3.5 w-3.5" />
                </div>
                <input
                  type="text"
                  placeholder="Search tactic, technique ID or name..."
                  value={reportSearch}
                  onChange={(e) => setReportSearch(e.target.value)}
                  className="w-full bg-slate-950/60 border border-slate-800 rounded-md py-1.5 pl-8 pr-3 text-xs text-slate-100 font-mono outline-none focus:border-blue-500"
                />
              </div>
              {reportData && reportData.length > 0 && (
                <div className="flex gap-2">
                  <button
                    onClick={exportAsPdf}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 border border-slate-800 text-slate-350 hover:text-slate-100 rounded text-[10px] font-mono uppercase tracking-wider font-bold transition cursor-pointer"
                  >
                    <Download className="h-3 w-3" />
                    <span>Download PDF</span>
                  </button>
                  <button
                    onClick={exportAsCsv}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600/10 border border-blue-500/20 text-blue-400 hover:text-blue-300 rounded text-[10px] font-mono uppercase tracking-wider font-bold transition cursor-pointer"
                  >
                    <FileDown className="h-3 w-3" />
                    <span>Download CSV</span>
                  </button>
                </div>
              )}
            </div>

            {/* Content Body */}
            <div className="p-5 overflow-y-auto space-y-4 flex-1">
              {loadingReport ? (
                <div className="py-16 text-center text-slate-400 font-mono text-[11px] uppercase tracking-widest animate-pulse">
                  Rendering threat indicators and gaps...
                </div>
              ) : reportData ? (
                <>
                  {/* Stats Badges */}
                  {(() => {
                    const counts = getReportSummaryCounts();
                    return (
                      <div className="grid grid-cols-3 gap-3 font-mono text-[10px] text-center">
                        <div className="bg-[#0F131A] border border-slate-800 p-2.5 rounded">
                          <span className="text-slate-500 block uppercase mb-0.5">Tactics with Gaps</span>
                          <span className="text-sm font-bold text-slate-200">{counts.tactics}</span>
                        </div>
                        <div className="bg-[#0F131A] border border-slate-800 p-2.5 rounded">
                          <span className="text-slate-500 block uppercase mb-0.5">Uncovered Parents</span>
                          <span className="text-sm font-bold text-rose-400">{counts.parents}</span>
                        </div>
                        <div className="bg-[#0F131A] border border-slate-800 p-2.5 rounded">
                          <span className="text-slate-500 block uppercase mb-0.5">Uncovered Subs</span>
                          <span className="text-sm font-bold text-amber-500">{counts.subs}</span>
                        </div>
                      </div>
                    );
                  })()}

                  <div className="space-y-4">
                    {getFilteredReport().length > 0 ? (
                      getFilteredReport().map((tactic) => (
                        <div key={tactic.tacticId} className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/25">
                          
                          {/* Tactic Header Block */}
                          <div className="bg-[#0F131A] px-3.5 py-2.5 border-b border-slate-800 flex justify-between items-center">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-[9px] font-bold text-slate-400 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">
                                {tactic.tacticId}
                              </span>
                              <h4 className="text-xs font-bold text-slate-200">
                                {tactic.name}
                              </h4>
                            </div>
                            <span className="text-[9px] font-mono font-bold text-slate-500 uppercase tracking-widest">
                              {tactic.uncoveredCount} Gap{tactic.uncoveredCount > 1 ? 's' : ''}
                            </span>
                          </div>

                          {/* Techniques Inside */}
                          <div className="divide-y divide-slate-800/40 p-1">
                            {tactic.techniques.map((tech: any) => (
                              <div key={tech.tid} className="p-3 space-y-2">
                                <div className="flex justify-between items-start gap-4">
                                  <div className="flex items-center gap-1.5">
                                    <span className="text-[10px] font-mono font-bold text-rose-400 bg-rose-500/10 px-1.5 py-0.2 rounded border border-rose-500/15">
                                      {tech.tid}
                                    </span>
                                    <span className="text-[11px] font-medium text-slate-300">
                                      {tech.name}
                                    </span>
                                  </div>
                                  <span className={`text-[8px] font-mono font-bold px-1.5 py-0.2 rounded border uppercase ${
                                    tech.covered 
                                      ? 'bg-emerald-500/10 border-emerald-500/15 text-emerald-400' 
                                      : 'bg-rose-500/10 border-rose-500/15 text-rose-400'
                                  }`}>
                                    Parent: {tech.covered ? 'COVERED' : 'UNCOVERED'}
                                  </span>
                                </div>

                                {/* Uncovered Sub-techniques */}
                                {tech.uncoveredSubTechniques && tech.uncoveredSubTechniques.length > 0 && (
                                  <div className="pl-4 border-l-2 border-slate-800/80 space-y-1.5 mt-1.5">
                                    <span className="text-[8px] font-mono text-slate-500 uppercase tracking-wider block font-bold">
                                      Uncovered Sub-techniques:
                                    </span>
                                    <div className="grid grid-cols-1 gap-1.5">
                                      {tech.uncoveredSubTechniques.map((sub: any) => (
                                        <div key={sub.tid} className="bg-slate-950/40 border border-slate-850 p-1.5 rounded flex items-center justify-between text-[10px]">
                                          <div className="flex items-center gap-1.5">
                                            <span className="text-[9px] font-mono font-semibold text-amber-500 bg-amber-500/10 px-1 rounded border border-amber-500/15">
                                              {sub.tid}
                                            </span>
                                            <span className="text-slate-400 font-medium">
                                              {sub.name}
                                            </span>
                                          </div>
                                          <span className="text-[7.5px] font-mono font-bold bg-amber-500/10 px-1.5 text-amber-400 rounded">
                                            UNMAPPED
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 border border-dashed border-slate-800 text-slate-550 text-slate-500 font-mono text-[10px] rounded-xl bg-[#0F131A] uppercase tracking-widest leading-relaxed">
                        No gaps matches found for &quot;{reportSearch}&quot;.
                      </div>
                    )}
                  </div>
                </>
              ) : (
                <div className="text-center py-8 text-slate-500 font-mono text-xs uppercase tracking-wide">
                  Analytical details retrieval error
                </div>
              )}
            </div>

            {/* Footer */}
            <div className="p-3 border-t border-slate-800 bg-[#0F131A] flex justify-end shrink-0">
              <button
                onClick={() => {
                  setShowReportModal(false);
                  setReportSearch('');
                }}
                className="bg-slate-900 border border-slate-850 text-slate-300 hover:text-slate-100 px-4 py-1.5 rounded text-[10px] font-mono uppercase tracking-wider font-bold transition cursor-pointer"
              >
                Close Report
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}
