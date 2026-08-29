import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  AlertTriangle,
  CheckCircle,
  ChevronDown,
  ChevronRight,
  Loader2,
  Play,
  ShieldAlert,
  Tag,
  XCircle,
} from 'lucide-react';
import { detectionApi } from '../services/api';
import type { DetectionResult } from '../types';

interface DetectionAnalysisProps {
  sessionUuid: string;
}

const statusStyles: Record<string, { label: string; badge: string; bar: string }> = {
  HIGH_RISK: {
    label: 'High Risk',
    badge: 'bg-red-500/20 text-red-400 border-red-500/40',
    bar: 'bg-red-500',
  },
  SUSPICIOUS: {
    label: 'Suspicious',
    badge: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
    bar: 'bg-amber-500',
  },
  NORMAL: {
    label: 'Normal',
    badge: 'bg-green-500/20 text-green-400 border-green-500/40',
    bar: 'bg-green-500',
  },
};

const severityColors: Record<string, string> = {
  high: 'text-red-400 bg-red-500/10 border-red-500/30',
  medium: 'text-amber-400 bg-amber-500/10 border-amber-500/30',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
};

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-slate-800/50 rounded-lg px-3 py-2">
      <p className="text-[11px] uppercase tracking-wider text-slate-500">{label}</p>
      <p className="text-sm text-white font-mono mt-0.5 truncate" title={value}>
        {value}
      </p>
    </div>
  );
}

function ResultCard({
  result,
  expanded,
  onToggle,
}: {
  result: DetectionResult;
  expanded: boolean;
  onToggle: () => void;
}) {
  const status = statusStyles[result.detection_status] || statusStyles.NORMAL;
  const riskScore = result.risk_score ?? 0;

  const encodingSummary = result.encoding_types && result.encoding_types.length > 0
    ? result.encoding_types.join(', ')
    : 'none';

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center justify-between gap-4 p-5 text-left hover:bg-slate-800/40 transition-colors"
      >
        <div className="flex items-center gap-4 min-w-0">
          {expanded ? (
            <ChevronDown className="w-5 h-5 text-slate-500 flex-shrink-0" />
          ) : (
            <ChevronRight className="w-5 h-5 text-slate-500 flex-shrink-0" />
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="font-mono text-white">{result.base_domain || 'unknown'}</span>
              <span className={`px-2 py-0.5 text-xs font-medium rounded-full border ${status.badge}`}>
                {status.label}
              </span>
            </div>
            <p className="text-xs text-slate-500 font-mono mt-1">
              {result.source_ip || 'unknown'} • {result.total_queries} queries
            </p>
          </div>
        </div>
        <div className="flex items-center gap-4 flex-shrink-0">
          <div className="text-right">
            <p className="text-xs text-slate-500">Risk Score</p>
            <p className="text-2xl font-bold font-mono text-white">{Math.round(riskScore)}</p>
          </div>
          <div className="w-32">
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className={`h-full ${status.bar} transition-all duration-500`}
                style={{ width: `${Math.min(100, riskScore)}%` }}
              />
            </div>
            <p className="text-xs text-slate-500 mt-1 text-right">
              {result.matched_rules_count} rule{result.matched_rules_count === 1 ? '' : 's'} matched
            </p>
          </div>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-dark-border p-5 space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            <Metric label="Total Queries" value={result.total_queries.toLocaleString()} />
            <Metric label="Unique Subdomains" value={result.unique_subdomains.toLocaleString()} />
            <Metric label="Avg Label Length" value={(result.avg_label_length ?? 0).toFixed(1)} />
            <Metric label="Max Label Length" value={String(result.max_label_length ?? 0)} />
            <Metric label="Avg Entropy" value={(result.avg_entropy ?? 0).toFixed(2)} />
            <Metric label="Max Entropy" value={(result.max_entropy ?? 0).toFixed(2)} />
            <Metric label="Encoding" value={encodingSummary} />
            <Metric label="Queries/min" value={(result.queries_per_minute ?? 0).toFixed(1)} />
            <Metric label="TXT Queries" value={String(result.txt_query_count)} />
            <Metric label="NULL Queries" value={String(result.null_query_count)} />
            <Metric label="NXDOMAIN Count" value={String(result.nxdomain_count)} />
            <Metric label="NXDOMAIN Ratio" value={((result.nxdomain_ratio ?? 0) * 100).toFixed(1) + '%'} />
          </div>

          <div>
            <div className="flex items-center gap-2 mb-3">
              <Tag className="w-4 h-4 text-slate-500" />
              <h4 className="text-sm font-medium text-white">Detection Indicators</h4>
            </div>
            <div className="space-y-2">
              {result.indicators.map((indicator) => (
                <div
                  key={indicator.id}
                  className={`flex items-start gap-3 p-3 rounded-lg border ${
                    indicator.matched
                      ? 'bg-slate-800/60 border-red-500/20'
                      : 'bg-slate-800/30 border-slate-700/50'
                  }`}
                >
                  <div className="mt-0.5 flex-shrink-0">
                    {indicator.matched ? (
                      <CheckCircle className="w-4 h-4 text-red-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-slate-600" />
                    )}
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono text-slate-500">{indicator.rule_id}</span>
                      <span className="text-sm font-medium text-white">{indicator.indicator_name}</span>
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border uppercase ${
                          severityColors[indicator.severity || 'low'] || severityColors.low
                        }`}
                      >
                        {indicator.severity || 'low'}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1">{indicator.explanation}</p>
                    <p className="text-xs text-slate-500 mt-1 font-mono">
                      {indicator.threshold !== null && indicator.threshold !== undefined
                        ? `Threshold: ${Number(indicator.threshold).toFixed(2)}`
                        : 'Threshold: n/a'}
                      {' • '}Observed:{' '}
                      {indicator.observed_value !== null && indicator.observed_value !== undefined
                        ? Number(indicator.observed_value).toFixed(2)
                        : 'n/a'}
                      {' • '}Weight: {Number(indicator.weight ?? 0).toFixed(1)}
                    </p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function DetectionAnalysis({ sessionUuid }: DetectionAnalysisProps) {
  const [results, setResults] = useState<DetectionResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<number | null>(null);

  const fetchResults = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await detectionApi.getDetectionResults(sessionUuid);
      setResults(data.results);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load detection results');
    } finally {
      setLoading(false);
    }
  }, [sessionUuid]);

  useEffect(() => {
    fetchResults();
  }, [fetchResults]);

  const handleRunDetection = async () => {
    setRunning(true);
    setError(null);
    setMessage(null);
    try {
      const data = await detectionApi.runDetection(sessionUuid);
      setResults(data.results);
      setMessage(
        data.results_count === 0
          ? 'Detection completed. No activity groups were identified.'
          : `Detection completed. Found ${data.results_count} activity group(s).`,
      );
      if (data.results.length > 0) {
        setExpanded(data.results[0].id);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to run detection');
    } finally {
      setRunning(false);
    }
  };

  const highRiskCount = results.filter((r) => r.detection_status === 'HIGH_RISK').length;
  const suspiciousCount = results.filter((r) => r.detection_status === 'SUSPICIOUS').length;
  const normalCount = results.filter((r) => r.detection_status === 'NORMAL').length;

  return (
    <div className="bg-dark-card border border-dark-border rounded-xl">
      <div className="p-5 border-b border-dark-border flex flex-col sm:flex-row gap-4 sm:items-center sm:justify-between">
        <div>
          <h2 className="text-lg font-medium text-white flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-primary-500" />
            Detection Analysis
          </h2>
          <p className="text-sm text-slate-400 mt-0.5">
            Rule-based risk scoring of extracted DNS queries
          </p>
        </div>
        <div className="flex items-center gap-3">
          {message && (
            <span className="text-sm text-green-400 flex items-center gap-1.5">
              <CheckCircle className="w-4 h-4" />
              {message}
            </span>
          )}
          <button
            onClick={handleRunDetection}
            disabled={running}
            className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg transition-colors"
          >
            {running ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            {running ? 'Analyzing...' : 'Run Detection'}
          </button>
        </div>
      </div>

      <div className="p-5">
        {error && (
          <div className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3 mb-4">
            <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <p className="text-red-300 text-sm">{error}</p>
          </div>
        )}

        {loading && (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-primary-500 animate-spin" />
          </div>
        )}

        {!loading && !error && results.length === 0 && (
          <div className="text-center py-12">
            <Activity className="w-12 h-12 text-slate-600 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">No Detection Results</h3>
            <p className="text-slate-400 text-sm max-w-md mx-auto mb-6">
              Run the rule-based detection engine to score the DNS queries extracted from this
              session for tunneling indicators.
            </p>
            <button
              onClick={handleRunDetection}
              disabled={running}
              className="inline-flex items-center gap-2 px-5 py-2.5 bg-primary-600 hover:bg-primary-700 disabled:opacity-50 text-white font-medium rounded-lg transition-colors"
            >
              {running ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Play className="w-4 h-4" />
              )}
              {running ? 'Analyzing...' : 'Run Detection'}
            </button>
          </div>
        )}

        {!loading && !error && results.length > 0 && (
          <div className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="bg-red-500/5 border border-red-500/20 rounded-lg p-4">
                <p className="text-sm text-slate-400">High Risk</p>
                <p className="text-3xl font-bold font-mono text-red-400">{highRiskCount}</p>
              </div>
              <div className="bg-amber-500/5 border border-amber-500/20 rounded-lg p-4">
                <p className="text-sm text-slate-400">Suspicious</p>
                <p className="text-3xl font-bold font-mono text-amber-400">{suspiciousCount}</p>
              </div>
              <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-4">
                <p className="text-sm text-slate-400">Normal</p>
                <p className="text-3xl font-bold font-mono text-green-400">{normalCount}</p>
              </div>
            </div>

            {results.map((result) => (
              <ResultCard
                key={result.id}
                result={result}
                expanded={expanded === result.id}
                onToggle={() => setExpanded(expanded === result.id ? null : result.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
