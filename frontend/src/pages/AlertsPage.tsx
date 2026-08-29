import { useEffect, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { 
  Search, Filter, ChevronLeft, ChevronRight, 
  AlertTriangle, CheckCircle, XCircle, RefreshCw,
  Bell, Shield, Globe, Server, BellRing
} from 'lucide-react';
import { alertApi } from '../services/api';
import type { Alert, AlertSeverity } from '../types';

export function AlertsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [sourceIpFilter, setSourceIpFilter] = useState('');
  const [domainFilter, setDomainFilter] = useState('');
  const [acknowledgedFilter, setAcknowledgedFilter] = useState<'all' | 'true' | 'false'>('all');

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      setError(null);
      const params = {
        skip: (page - 1) * pageSize,
        limit: pageSize,
        ...(severityFilter && { severity: severityFilter }),
        ...(sourceIpFilter && { source_ip: sourceIpFilter }),
        ...(domainFilter && { domain: domainFilter }),
        ...(acknowledgedFilter !== 'all' && { acknowledged: acknowledgedFilter === 'true' }),
      };
      const data = await alertApi.listAlerts(params);
      setAlerts(data.alerts);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlerts();
  }, [page, severityFilter, sourceIpFilter, domainFilter, acknowledgedFilter]);

  const handleFilterChange = (key: string, value: string) => {
    setSearchParams({ [key]: value });
    setPage(1);
    if (key === 'severity') setSeverityFilter(value);
    if (key === 'source_ip') setSourceIpFilter(value);
    if (key === 'domain') setDomainFilter(value);
    if (key === 'acknowledged') setAcknowledgedFilter(value as any);
  };

  const totalPages = Math.ceil(total / pageSize);

  const getSeverityBadge = (severity: AlertSeverity) => {
    const styles: Record<AlertSeverity, string> = {
      LOW: 'bg-blue-500/20 text-blue-400',
      MEDIUM: 'bg-amber-500/20 text-amber-400',
      HIGH: 'bg-orange-500/20 text-orange-400',
      CRITICAL: 'bg-red-500/20 text-red-400',
    };
    const icons: Record<AlertSeverity, any> = {
      LOW: CheckCircle,
      MEDIUM: AlertTriangle,
      HIGH: XCircle,
      CRITICAL: BellRing,
    };
    const Icon = icons[severity];
    return (
      <span className={`inline-flex items-center gap-1 px-3 py-1 rounded-full text-sm font-medium ${styles[severity]}`}>
        <Icon className="w-4 h-4" />
        {severity}
      </span>
    );
  };

  const formatTimestamp = (ts: string) => {
    return new Date(ts).toLocaleString();
  };

  if (loading && alerts.length === 0) {
    return (
      <div className="p-8 max-w-7xl mx-auto flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2 flex items-center gap-2">
          <Bell className="w-8 h-8" />
          Alerts
        </h1>
        <p className="text-slate-400">Monitor and investigate DNS tunneling alerts</p>
      </div>

      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden mb-8">
        <div className="p-4 border-b border-dark-border">
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search by source IP..."
                value={sourceIpFilter}
                onChange={(e) => handleFilterChange('source_ip', e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary-500 text-sm"
              />
            </div>
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search by domain..."
                value={domainFilter}
                onChange={(e) => handleFilterChange('domain', e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary-500 text-sm"
              />
            </div>
            <select
              value={severityFilter}
              onChange={(e) => handleFilterChange('severity', e.target.value)}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500 w-40"
            >
              <option value="">All Severities</option>
              <option value="LOW">Low</option>
              <option value="MEDIUM">Medium</option>
              <option value="HIGH">High</option>
              <option value="CRITICAL">Critical</option>
            </select>
            <select
              value={acknowledgedFilter}
              onChange={(e) => handleFilterChange('acknowledged', e.target.value)}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500 w-40"
            >
              <option value="all">All</option>
              <option value="true">Acknowledged</option>
              <option value="false">Unacknowledged</option>
            </select>
            <button
              onClick={fetchAlerts}
              disabled={loading}
              className="px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white text-sm rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </button>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border bg-slate-800/50">
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Severity</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Domain</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Query Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Risk Score</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {alerts.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-12 text-center text-slate-500">
                    No alerts match the current filters
                  </td>
                </tr>
              ) : (
                alerts.map((alert) => (
                  <tr key={alert.id} className="hover:bg-slate-800/50 transition-colors cursor-pointer">
                    <td className="px-4 py-3">
                      {getSeverityBadge(alert.severity)}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                      {formatTimestamp(alert.created_at)}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-300 font-mono">
                      {alert.source_ip || '—'}
                    </td>
                    <td className="px-4 py-3 text-sm text-slate-300 truncate max-w-xs" title={alert.domain || ''}>
                      {alert.domain || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                      {alert.query_type || '—'}
                    </td>
                    <td className="px-4 py-3">
                      <span className="font-mono text-white font-bold">
                        {alert.risk_score} / 100
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex px-2 py-0.5 text-xs rounded ${alert.acknowledged ? 'bg-green-500/20 text-green-400' : 'bg-amber-500/20 text-amber-400'}`}>
                        {alert.acknowledged ? 'Acknowledged' : 'New'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <Link
                        to={`/alerts/${alert.id}`}
                        className="text-primary-400 hover:text-primary-300 text-sm font-medium"
                      >
                        Investigate
                      </Link>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {totalPages > 1 && (
          <div className="p-4 border-t border-dark-border flex items-center justify-between">
            <p className="text-sm text-slate-400">
              Page {page} of {totalPages} • {total.toLocaleString()} total
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={page === 1 || loading}
                className="px-3 py-1 text-sm bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages || loading}
                className="px-3 py-1 text-sm bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}