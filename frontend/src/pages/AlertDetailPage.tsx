import { useEffect, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import { 
  AlertTriangle, CheckCircle, XCircle, Shield, Globe, Server, 
  Bell, BellRing, ChevronLeft, RefreshCw, AlertCircle,
  UserCheck, Clock, Hash, BarChart2, FileText
} from 'lucide-react';
import { alertApi } from '../services/api';
import type { Alert, AlertSeverity, AlertAcknowledgeRequest } from '../types';

export function AlertDetailPage() {
  const { alertId } = useParams<{ alertId: string }>();
  const navigate = useNavigate();
  const [alert, setAlert] = useState<Alert | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [acknowledging, setAcknowledging] = useState(false);
  const [ackUser, setAckUser] = useState('');

  const fetchAlert = async () => {
    if (!alertId) return;
    try {
      setLoading(true);
      setError(null);
      const data = await alertApi.getAlert(parseInt(alertId, 10));
      setAlert(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load alert');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAlert();
  }, [alertId]);

  const handleAcknowledge = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!alert || !ackUser.trim()) return;
    
    setAcknowledging(true);
    try {
      const data = await alertApi.acknowledgeAlert(alert.id, { acknowledged_by: ackUser });
      setAlert(data);
      setAckUser('');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to acknowledge alert');
    } finally {
      setAcknowledging(false);
    }
  };

  const getSeverityInfo = (severity: AlertSeverity) => {
    const info: Record<AlertSeverity, { label: string; color: string; icon: any; bg: string }> = {
      LOW: { label: 'LOW', color: 'text-blue-400', icon: CheckCircle, bg: 'bg-blue-500/10' },
      MEDIUM: { label: 'MEDIUM', color: 'text-amber-400', icon: AlertTriangle, bg: 'bg-amber-500/10' },
      HIGH: { label: 'HIGH', color: 'text-orange-400', icon: XCircle, bg: 'bg-orange-500/10' },
      CRITICAL: { label: 'CRITICAL', color: 'text-red-400', icon: BellRing, bg: 'bg-red-500/10' },
    };
    return info[severity];
  };

  const formatTimestamp = (ts: string | null) => {
    if (!ts) return '—';
    return new Date(ts).toLocaleString();
  };

  if (loading) {
    return (
      <div className="p-8 max-w-7xl mx-auto flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (error || !alert) {
    return (
      <div className="p-8 max-w-4xl mx-auto text-center">
        <AlertCircle className="w-16 h-16 text-red-500 mx-auto mb-4" />
        <h1 className="text-2xl font-bold text-white mb-2">Alert Not Found</h1>
        <p className="text-slate-400 mb-6">{error || 'Alert does not exist'}</p>
        <Link to="/alerts" className="inline-flex items-center gap-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 text-white rounded-lg">
          <ChevronLeft className="w-4 h-4" />
          Back to Alerts
        </Link>
      </div>
    );
  }

  const severityInfo = getSeverityInfo(alert.severity);
  const SeverityIcon = severityInfo.icon;

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <Link
            to="/alerts"
            className="text-sm text-primary-400 hover:text-primary-300 mb-2 inline-block"
          >
            <ChevronLeft className="w-4 h-4 inline mr-1" />
            Back to Alerts
          </Link>
          <div className="flex items-center gap-4">
            <h1 className="text-3xl font-bold text-white">Alert Investigation</h1>
            <span className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium ${severityInfo.bg} ${severityInfo.color}`}>
              <SeverityIcon className="w-5 h-5" />
              {severityInfo.label}
            </span>
            {!alert.acknowledged && (
              <span className="inline-flex items-center gap-1 px-3 py-1.5 bg-amber-500/20 text-amber-400 rounded-lg text-sm font-medium">
                <Bell className="w-4 h-4" />
                Unacknowledged
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fetchAlert}
            disabled={loading}
            className="px-4 py-2 bg-slate-800 border border-slate-700 hover:bg-slate-700 text-white text-sm rounded-lg flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Overview
              </h2>
            </div>
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-slate-500 text-sm mb-1">Alert ID</p>
                <p className="font-mono text-sm text-white bg-slate-800 px-3 py-2 rounded">{alert.alert_id}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Detection Result ID</p>
                <p className="font-mono text-sm text-white bg-slate-800 px-3 py-2 rounded">{alert.detection_result_id}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Created</p>
                <p className="font-mono text-sm text-white bg-slate-800 px-3 py-2 rounded">{formatTimestamp(alert.created_at)}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Acknowledged</p>
                <p className="font-mono text-sm text-white bg-slate-800 px-3 py-2 rounded">
                  {alert.acknowledged ? formatTimestamp(alert.acknowledged_at) : 'No'}
                </p>
              </div>
              <div className="md:col-span-2">
                <p className="text-slate-500 text-sm mb-1">Risk Score</p>
                <div className="flex items-center gap-4">
                  <div className="flex-1 h-4 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-500 ${
                        alert.severity === 'CRITICAL' ? 'bg-red-500' :
                        alert.severity === 'HIGH' ? 'bg-orange-500' :
                        alert.severity === 'MEDIUM' ? 'bg-amber-500' : 'bg-blue-500'
                      }`}
                      style={{ width: `${alert.risk_score}%` }}
                    />
                  </div>
                  <span className="font-mono text-white text-lg font-bold w-16 text-right">
                    {alert.risk_score} / 100
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Network Information
              </h2>
            </div>
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-slate-500 text-sm mb-1">Source IP</p>
                <p className="font-mono text-white text-lg">{alert.source_ip || '—'}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Destination IP</p>
                <p className="font-mono text-white text-lg">{alert.destination_ip || '—'}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Queried Domain</p>
                <p className="font-mono text-white text-lg truncate max-w-xs">{alert.domain || '—'}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Normalized Domain</p>
                <p className="font-mono text-white text-lg truncate max-w-xs">{alert.normalized_domain || '—'}</p>
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-1">Query Type</p>
                <p className="font-mono text-white text-lg">{alert.query_type || '—'}</p>
              </div>
            </div>
          </div>

          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <Hash className="w-5 h-5" />
                Matched Detection Rules
              </h2>
            </div>
            <div className="p-6">
              {alert.matched_rules && alert.matched_rules.length > 0 ? (
                <div className="space-y-4">
                  {alert.matched_rules.map((rule: any, idx: number) => (
                    <div key={idx} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3 mb-3">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-primary-400 text-sm">{rule.rule_id}</span>
                          <span className="text-white font-medium">{rule.indicator}</span>
                        </div>
                        <span className={`px-2 py-1 text-xs rounded ${rule.severity === 'high' ? 'bg-red-500/20 text-red-400' : rule.severity === 'medium' ? 'bg-amber-500/20 text-amber-400' : 'bg-blue-500/20 text-blue-400'}`}>
                          {(rule.severity || 'low').toUpperCase()}
                        </span>
                      </div>
                      <p className="text-sm text-white mb-3">{rule.explanation}</p>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                        <div>
                          <p className="text-slate-500">Threshold</p>
                          <p className="font-mono text-slate-300">{rule.threshold !== undefined ? rule.threshold : 'N/A'}</p>
                        </div>
                        <div>
                          <p className="text-slate-500">Observed</p>
                          <p className="font-mono text-white">{rule.observed_value !== undefined ? rule.observed_value : 'N/A'}</p>
                        </div>
                        <div>
                          <p className="text-slate-500">Weight</p>
                          <p className="font-mono text-slate-300">{rule.weight !== undefined ? rule.weight : 'N/A'}</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <Shield className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400">No matched rules recorded</p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Why Was This Detected?
              </h2>
            </div>
            <div className="p-6">
              {alert.detection_reasons && alert.detection_reasons.length > 0 ? (
                <ul className="space-y-3">
                  {alert.detection_reasons.map((reason: any, idx: number) => (
                    <li key={idx} className="bg-slate-800/50 border border-slate-700 rounded-lg p-4 flex items-start gap-3">
                      <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
                      <div>
                        <p className="font-medium text-white">{reason.rule}</p>
                        <p className="text-sm text-slate-300 mt-1">{reason.reason}</p>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-center py-8">
                  <FileText className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                  <p className="text-slate-400">No detection reasons recorded</p>
                </div>
              )}
            </div>
          </div>

          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <BarChart2 className="w-5 h-5" />
                Observed Values & Thresholds
              </h2>
            </div>
            <div className="p-6 grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <p className="text-slate-500 text-sm mb-3">Observed Values</p>
                {alert.observed_values && Object.keys(alert.observed_values).length > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {Object.entries(alert.observed_values).map(([key, value]) => (
                      <div key={key} className="bg-slate-800/50 rounded-lg p-3 flex justify-between">
                        <span className="font-mono text-primary-400 text-sm">{key}</span>
                        <span className="font-mono text-white">{JSON.stringify(value)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500">No observed values recorded</p>
                )}
              </div>
              <div>
                <p className="text-slate-500 text-sm mb-3">Thresholds</p>
                {alert.thresholds && Object.keys(alert.thresholds).length > 0 ? (
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {Object.entries(alert.thresholds).map(([key, value]) => (
                      <div key={key} className="bg-slate-800/50 rounded-lg p-3 flex justify-between">
                        <span className="font-mono text-primary-400 text-sm">{key}</span>
                        <span className="font-mono text-slate-300">{JSON.stringify(value)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500">No thresholds recorded</p>
                )}
              </div>
              <div className="md:col-span-2">
                <p className="text-slate-500 text-sm mb-3">Rule Weights</p>
                {alert.rule_weights && Object.keys(alert.rule_weights).length > 0 ? (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                    {Object.entries(alert.rule_weights).map(([key, value]) => (
                      <div key={key} className="bg-slate-800/50 rounded-lg p-3">
                        <p className="font-mono text-primary-400 text-sm">{key}</p>
                        <p className="font-mono text-white text-lg font-bold">{value}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-slate-500">No rule weights recorded</p>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="space-y-6">
          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
<div className="p-6 border-b border-dark-border">
            <h2 className="text-lg font-medium text-white flex items-center gap-2">
              <BellRing className="w-5 h-5" />
              Acknowledge Alert
            </h2>
          </div>
            <div className="p-6">
              {alert.acknowledged ? (
                <div className="bg-green-500/10 border border-green-500/30 rounded-lg p-4">
                  <div className="flex items-center gap-3">
                    <CheckCircle className="w-5 h-5 text-green-400" />
                    <div>
                      <p className="font-medium text-green-300">Alert Acknowledged</p>
                      <p className="text-sm text-slate-400 mt-1">
                        By: <span className="text-white font-mono">{alert.acknowledged_by}</span>
                        <span className="mx-2">•</span>
                        At: <span className="text-white font-mono">{formatTimestamp(alert.acknowledged_at)}</span>
                      </p>
                    </div>
                  </div>
                </div>
              ) : (
                <form onSubmit={handleAcknowledge} className="space-y-4">
                  <div>
                    <label htmlFor="ackUser" className="block text-sm text-slate-400 mb-2">
                      Your Name / Identifier
                    </label>
                    <input
                      id="ackUser"
                      type="text"
                      value={ackUser}
                      onChange={(e) => setAckUser(e.target.value)}
                      placeholder="e.g., analyst_john"
                      required
                      className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary-500"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={acknowledging || !ackUser.trim()}
                    className="w-full py-2.5 bg-amber-600 hover:bg-amber-700 disabled:bg-amber-500/50 disabled:cursor-not-allowed text-white font-medium rounded-lg flex items-center justify-center gap-2 transition-colors"
                  >
                    {acknowledging ? (
                      <>
                        <RefreshCw className="w-5 h-5 animate-spin" />
                        Acknowledging...
                      </>
                    ) : (
                      <>
                        <UserCheck className="w-5 h-5" />
                        Acknowledge Alert
                      </>
                    )}
                  </button>
                </form>
              )}
            </div>
          </div>

          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <Clock className="w-5 h-5" />
                Recommended Action
              </h2>
            </div>
            <div className="p-6">
              <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                {alert.severity === 'CRITICAL' && (
                  <div className="space-y-3 text-sm text-slate-300">
                    <p className="font-medium text-white flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      Immediate Investigation Required
                    </p>
                    <ul className="list-disc list-inside space-y-1 pl-4">
                      <li>This alert indicates a high-confidence DNS tunneling attempt</li>
                      <li>Isolate the source IP <code className="bg-slate-900 px-1.5 py-0.5 rounded text-primary-400 font-mono text-xs">{alert.source_ip}</code> immediately</li>
                      <li>Review all DNS queries from this source in the last 24 hours</li>
                      <li>Check for data exfiltration or C2 communication</li>
                      <li>Block the domain <code className="bg-slate-900 px-1.5 py-0.5 rounded text-primary-400 font-mono text-xs">{alert.domain}</code> at DNS firewall</li>
                      <li>Escalate to incident response team</li>
                    </ul>
                  </div>
                )}
                {alert.severity === 'HIGH' && (
                  <div className="space-y-3 text-sm text-slate-300">
                    <p className="font-medium text-white flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-orange-400" />
                      Urgent Investigation Required
                    </p>
                    <ul className="list-disc list-inside space-y-1 pl-4">
                      <li>Strong indicators of DNS tunneling detected</li>
                      <li>Review source IP <code className="bg-slate-900 px-1.5 py-0.5 rounded text-primary-400 font-mono text-xs">{alert.source_ip}</code> activity</li>
                      <li>Monitor for continued suspicious DNS queries</li>
                      <li>Consider blocking the queried domain</li>
                    </ul>
                  </div>
                )}
                {alert.severity === 'MEDIUM' && (
                  <div className="space-y-3 text-sm text-slate-300">
                    <p className="font-medium text-white flex items-center gap-2">
                      <AlertTriangle className="w-5 h-5 text-amber-400" />
                      Elevated Risk - Monitor Closely
                    </p>
                    <ul className="list-disc list-inside space-y-1 pl-4">
                      <li>Some suspicious DNS patterns detected</li>
                      <li>Increase monitoring on source IP</li>
                      <li>Review if this is legitimate high-volume DNS traffic</li>
                      <li>Consider adding to watchlist</li>
                    </ul>
                  </div>
                )}
                {alert.severity === 'LOW' && (
                  <div className="space-y-3 text-sm text-slate-300">
                    <p className="font-medium text-white flex items-center gap-2">
                      <CheckCircle className="w-5 h-5 text-blue-400" />
                      Low Risk - Routine Monitoring
                    </p>
                    <ul className="list-disc list-inside space-y-1 pl-4">
                      <li>Minimal suspicious indicators</li>
                      <li>Continue standard monitoring</li>
                      <li>No immediate action required</li>
                    </ul>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}