import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Globe, Server, AlertCircle, CheckCircle, XCircle, 
  Shield, AlertTriangle, Activity, Zap, 
  ChevronRight, ChevronLeft, RefreshCw, 
  Search, Filter, Download, FileText,
  Hash, BarChart2
} from 'lucide-react';
import { pcapApi, detectionApi } from '../services/api';
import type { AnalysisSession, DetectionResult, DetectionRunResponse, DetectionStatus } from '../types';

export function DetectionPage() {
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get('session');
  
  const [session, setSession] = useState<AnalysisSession | null>(null);
  const [detectionResults, setDetectionResults] = useState<DetectionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [runningDetection, setRunningDetection] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runResponse, setRunResponse] = useState<DetectionRunResponse | null>(null);

  const fetchSession = async () => {
    if (!sessionId) return;
    try {
      const data = await pcapApi.getSession(sessionId);
      setSession(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load session');
    }
  };

  const fetchDetectionResults = async () => {
    if (!sessionId) return;
    try {
      const data = await detectionApi.getDetectionResults(sessionId);
      setDetectionResults(data.results);
    } catch (err: any) {
      // No detection results yet is not an error
      if (err.response?.status !== 404) {
        console.warn('No detection results found');
      }
    }
  };

  const handleRunDetection = async () => {
    if (!sessionId) return;
    
    setRunningDetection(true);
    setError(null);
    setRunResponse(null);
    
    try {
      const response = await detectionApi.runDetection(sessionId);
      setRunResponse(response);
      if (response.results_count > 0) {
        setDetectionResults(response.results);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Detection failed');
    } finally {
      setRunningDetection(false);
    }
  };

  useEffect(() => {
    fetchSession();
    fetchDetectionResults();
  }, [sessionId]);

  const getStatusBadge = (status: DetectionStatus) => {
    const styles: Record<DetectionStatus, string> = {
      NORMAL: 'bg-green-500/20 text-green-400',
      SUSPICIOUS: 'bg-amber-500/20 text-amber-400',
      HIGH_RISK: 'bg-red-500/20 text-red-400',
    };
    const icons: Record<DetectionStatus, any> = {
      NORMAL: CheckCircle,
      SUSPICIOUS: AlertTriangle,
      HIGH_RISK: XCircle,
    };
    const Icon = icons[status];
    return (
      <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${styles[status]}`}>
        <Icon className="w-4 h-4" />
        {status}
      </span>
    );
  };

  const getSeverityBadge = (severity: string | null) => {
    const styles: Record<string, string> = {
      high: 'bg-red-500/20 text-red-400',
      medium: 'bg-amber-500/20 text-amber-400',
      low: 'bg-blue-500/20 text-blue-400',
    };
    return (
      <span className={`px-2 py-0.5 text-xs rounded ${styles[severity || 'low']}`}>
        {severity?.toUpperCase() || 'LOW'}
      </span>
    );
  };

  if (!sessionId) {
    return (
      <div className="p-8 max-w-4xl mx-auto text-center">
        <Globe className="w-16 h-16 text-slate-700 mx-auto mb-4" />
        <h1 className="text-2xl font-bold text-white mb-2">No Session Selected</h1>
        <p className="text-slate-400 mb-6">Select a session from the dashboard or upload a new PCAP file</p>
        <a href="/upload" className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg">
          Upload PCAP
        </a>
      </div>
    );
  }

  if (loading && detectionResults.length === 0) {
    return (
      <div className="p-8 max-w-4xl mx-auto flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {session && (
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-2xl font-bold text-white">{session.original_filename}</h1>
              <p className="text-slate-400">
                Session: <code className="font-mono text-xs">{session.session_id}</code>
              </p>
            </div>
            <div className="flex items-center gap-4">
              <span className={`px-3 py-1 rounded-full text-sm font-medium ${
                session.processing_status === 'completed' ? 'bg-green-500/20 text-green-400' :
                session.processing_status === 'failed' ? 'bg-red-500/20 text-red-400' :
                'bg-amber-500/20 text-amber-400'
              }`}>
                {session.processing_status}
              </span>
            </div>
          </div>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-slate-500">Total Packets</p>
              <p className="text-white font-mono text-2xl">{session.total_packets.toLocaleString()}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-slate-500">DNS Packets</p>
              <p className="text-white font-mono text-2xl">{session.dns_packets.toLocaleString()}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-slate-500">Queries Extracted</p>
              <p className="text-white font-mono text-2xl">{session.queries_extracted.toLocaleString()}</p>
            </div>
            <div className="bg-dark-card border border-dark-border rounded-lg p-4">
              <p className="text-slate-500">Processing Time</p>
              <p className="text-white font-mono text-2xl">{session.processing_duration_ms}ms</p>
            </div>
          </div>
        </div>
      )}

      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden mb-8">
        <div className="p-6 border-b border-dark-border flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <h2 className="text-lg font-medium text-white flex items-center gap-2">
            <Shield className="w-5 h-5" />
            DNS Tunneling Detection
          </h2>
          <button
            onClick={handleRunDetection}
            disabled={runningDetection || !session || session.queries_extracted === 0}
            className="px-6 py-2.5 bg-primary-600 hover:bg-primary-700 disabled:bg-primary-500/50 disabled:cursor-not-allowed text-white font-medium rounded-lg flex items-center gap-2 transition-colors"
          >
            <RefreshCw className={`w-5 h-5 ${runningDetection ? 'animate-spin' : ''}`} />
            {runningDetection ? 'Running Detection...' : 'Run Detection'}
          </button>
        </div>

        {runResponse && (
          <div className={`p-4 border-b border-dark-border ${runResponse.success ? 'bg-green-500/5' : 'bg-red-500/5'}`}>
            <div className="flex items-center gap-3">
              {runResponse.success ? (
                <CheckCircle className="w-5 h-5 text-green-400" />
              ) : (
                <AlertCircle className="w-5 h-5 text-red-400" />
              )}
              <p className={runResponse.success ? 'text-green-300' : 'text-red-300'}>
                {runResponse.message}
              </p>
            </div>
          </div>
        )}

        {error && (
          <div className="p-4 border-b border-dark-border bg-red-500/5">
            <div className="flex items-center gap-3">
              <AlertCircle className="w-5 h-5 text-red-400" />
              <p className="text-red-300">{error}</p>
            </div>
          </div>
        )}

        {detectionResults.length === 0 && !runningDetection && !runResponse && (
          <div className="p-12 text-center">
            <Shield className="w-16 h-16 text-slate-700 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Detection Analysis Available</h3>
            <p className="text-slate-400 mb-6 max-w-md mx-auto">
              Run detection on this session to analyze DNS queries for potential tunneling indicators.
            </p>
            {session.queries_extracted === 0 && (
              <p className="text-amber-400 text-sm">This session has no DNS queries to analyze.</p>
            )}
          </div>
        )}

        {detectionResults.length > 0 && (
          <div className="p-6">
            <div className="mb-6">
              <h3 className="text-lg font-medium text-white mb-4">Detection Results ({detectionResults.length} activity group(s))</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {detectionResults.map((result) => (
                  <div key={result.id} className="bg-slate-800/50 border border-dark-border rounded-xl p-6">
                    <div className="flex items-start justify-between mb-4">
                      <div>
                        <p className="font-mono text-sm text-slate-400 mb-1">{result.source_ip || 'Unknown IP'}</p>
                        <p className="font-medium text-white truncate">{result.base_domain || 'Unknown Domain'}</p>
                      </div>
                      {getStatusBadge(result.detection_status)}
                    </div>

                    <div className="space-y-3 mb-4">
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Risk Score</span>
                        <span className="font-mono text-white font-bold">
                          {result.risk_score !== null ? result.risk_score.toFixed(1) : 'N/A'} / 100
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Matched Rules</span>
                        <span className="font-mono text-white">{result.matched_rules_count} / 8</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Total Queries</span>
                        <span className="font-mono text-white">{result.total_queries.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Unique Subdomains</span>
                        <span className="font-mono text-white">{result.unique_subdomains.toLocaleString()}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Max Label Length</span>
                        <span className="font-mono text-white">{result.max_label_length || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Max Entropy</span>
                        <span className="font-mono text-white">{result.max_entropy !== null ? result.max_entropy.toFixed(2) : 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Queries/Min</span>
                        <span className="font-mono text-white">{result.queries_per_minute !== null ? result.queries_per_minute.toFixed(1) : 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">NXDOMAIN Ratio</span>
                        <span className="font-mono text-white">
                          {result.nxdomain_ratio !== null ? (result.nxdomain_ratio * 100).toFixed(1) + '%' : 'N/A'}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Encoding Detected</span>
                        <span className="font-mono text-white">
                          {result.encoding_detected ? result.encoding_types?.join(', ') || 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-slate-400">Burst Detected</span>
                        <span className="font-mono text-white">
                          {result.burst_detected ? 'Yes' : 'No'}
                        </span>
                      </div>
                    </div>

                    {result.indicators && result.indicators.length > 0 && (
                      <div className="border-t border-dark-border pt-4">
                        <h4 className="text-sm font-medium text-slate-300 mb-3">Matched Indicators</h4>
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {result.indicators.filter(i => i.matched).map((indicator) => (
                            <div key={indicator.id} className="bg-slate-900/50 rounded-lg p-3">
                              <div className="flex items-start justify-between gap-2 mb-1">
                                <span className="font-mono text-xs text-primary-400">{indicator.rule_id}</span>
                                {getSeverityBadge(indicator.severity)}
                              </div>
                              <p className="text-sm text-white font-medium">{indicator.indicator_name}</p>
                              <p className="text-xs text-slate-400 mt-1">{indicator.explanation}</p>
                              <div className="flex items-center gap-4 mt-2 text-xs text-slate-500">
                                <span>Threshold: <span className="text-slate-300 font-mono">
                                  {indicator.threshold !== null ? indicator.threshold.toFixed(2) : 'N/A'}
                                </span></span>
                                <span>Observed: <span className="text-slate-300 font-mono">
                                  {indicator.observed_value !== null ? indicator.observed_value.toFixed(2) : 'N/A'}
                                </span></span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}