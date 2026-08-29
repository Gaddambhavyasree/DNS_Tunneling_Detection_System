import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shield, FileText, Database, AlertTriangle, Upload, BarChart2, Bell, Globe, TrendingUp, CheckCircle } from 'lucide-react';
import { pcapApi, alertApi } from '../services/api';
import type { AnalysisSessionList, HealthResponse, AlertList } from '../types';

export function Dashboard() {
  const [sessions, setSessions] = useState<AnalysisSessionList['sessions']>([]);
  const [totalSessions, setTotalSessions] = useState(0);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [alertsData, setAlertsData] = useState<AlertList | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      const [sessionsRes, healthRes, alertsRes] = await Promise.all([
        pcapApi.getSessions(0, 10),
        healthApi.check(),
        alertApi.listAlerts({ limit: 100 }),
      ]);
      setSessions(sessionsRes.sessions);
      setTotalSessions(sessionsRes.total);
      setHealth(healthRes);
      setAlertsData(alertsRes);
    } catch (err: any) {
      setError(err.message || 'Failed to load dashboard data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const alerts = alertsData?.alerts || [];
  const highRiskAlerts = alerts.filter(a => a.severity === 'HIGH' || a.severity === 'CRITICAL').length || 0;
  const totalAlerts = alertsData?.total || 0;
  const newAlerts = alerts.filter(a => !a.acknowledged).length || 0;

  const stats = [
    {
      label: 'Total Sessions',
      value: totalSessions,
      icon: FileText,
      color: 'text-blue-400',
      bg: 'bg-blue-500/10',
    },
    {
      label: 'DNS Queries',
      value: sessions.reduce((sum, s) => sum + s.queries_extracted, 0),
      icon: Database,
      color: 'text-green-400',
      bg: 'bg-green-500/10',
    },
    {
      label: 'Total Packets',
      value: sessions.reduce((sum, s) => sum + s.total_packets, 0),
      icon: Shield,
      color: 'text-purple-400',
      bg: 'bg-purple-500/10',
    },
    {
      label: 'Total Alerts',
      value: totalAlerts,
      icon: Bell,
      color: 'text-red-400',
      bg: 'bg-red-500/10',
    },
    {
      label: 'High/Critical',
      value: highRiskAlerts,
      icon: AlertTriangle,
      color: 'text-orange-400',
      bg: 'bg-orange-500/10',
    },
    {
      label: 'Unacknowledged',
      value: newAlerts,
      icon: TrendingUp,
      color: 'text-amber-400',
      bg: 'bg-amber-500/10',
    },
    {
      label: 'DNS Queries (All)',
      value: alerts.reduce((sum, a) => sum + (a.risk_score > 70 ? 1 : 0), 0),
      icon: Globe,
      color: 'text-cyan-400',
      bg: 'bg-cyan-500/10',
    },
    {
      label: 'Status',
      value: health?.database_connected ? 'Connected' : 'Disconnected',
      icon: health?.database_connected ? CheckCircle : AlertTriangle,
      color: health?.database_connected ? 'text-green-400' : 'text-red-400',
      bg: health?.database_connected ? 'bg-green-500/10' : 'bg-red-500/10',
    },
  ];

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-4 border-primary-500 border-t-transparent" />
      </div>
    );
  }

  if (totalSessions === 0) {
    return (
      <div className="p-8 max-w-4xl mx-auto">
        {error && (
          <div className="mb-6 p-4 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm">
            Could not reach the backend API: {error}. Make sure the backend is deployed and{' '}
            <code className="font-mono">VITE_API_BASE_URL</code> is set correctly.
          </div>
        )}
        <div className="text-center py-16">
          <Shield className="w-24 h-24 text-slate-700 mx-auto mb-6" />
          <h1 className="text-3xl font-bold text-white mb-4">NO DNS DATA AVAILABLE</h1>
          <p className="text-slate-400 text-lg mb-8 max-w-md mx-auto">
            Upload a PCAP/PCAPNG file to begin DNS traffic analysis.
            The system will extract DNS queries and prepare them for tunneling detection.
          </p>
          <Link
            to="/upload"
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
          >
            <Upload className="w-5 h-5" />
            Upload PCAP File
          </Link>
        </div>

        <div className="mt-12 grid md:grid-cols-3 gap-6">
          {[
            { icon: FileText, title: 'PCAP/PCAPNG Upload', desc: 'Upload packet captures for DNS extraction' },
            { icon: Database, title: 'DNS Query Storage', desc: 'All queries stored in local SQLite database' },
            { icon: BarChart2, title: 'Rule-Based Analysis', desc: 'Explainable detection (no ML)' },
          ].map((item, i) => (
            <div key={i} className="bg-dark-card border border-dark-border rounded-xl p-6 text-center">
              <item.icon className="w-12 h-12 text-primary-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-white mb-2">{item.title}</h3>
              <p className="text-slate-400 text-sm">{item.desc}</p>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-7xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Dashboard</h1>
        <p className="text-slate-400">Overview of DNS analysis sessions</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat, i) => (
          <div key={i} className="bg-dark-card border border-dark-border rounded-xl p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-400">{stat.label}</p>
                <p className="text-3xl font-bold text-white mt-1">{stat.value}</p>
              </div>
              <div className={`${stat.bg} ${stat.color} p-3 rounded-lg`}>
                <stat.icon className="w-6 h-6" />
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
        <div className="p-6 border-b border-dark-border flex items-center justify-between">
          <h2 className="text-lg font-medium text-white">Recent Sessions</h2>
          <Link to="/upload" className="text-sm text-primary-400 hover:text-primary-300">
            New Upload
          </Link>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border">
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Session</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">File</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Packets</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">DNS Queries</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Status</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Duration</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Uploaded</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {sessions.map((session) => (
                <tr key={session.id} className="hover:bg-slate-800/50 transition-colors cursor-pointer">
                  <td className="px-6 py-4">
                    <code className="text-xs text-slate-400 font-mono">{session.session_id.slice(0, 12)}...</code>
                  </td>
                  <td className="px-6 py-4">
                    <p className="text-sm text-white truncate max-w-xs">{session.original_filename}</p>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300 font-mono">{session.total_packets.toLocaleString()}</td>
                  <td className="px-6 py-4 text-sm text-slate-300 font-mono">{session.queries_extracted.toLocaleString()}</td>
                  <td className="px-6 py-4">
                    <span className={`inline-flex px-2 py-1 text-xs font-medium rounded-full ${
                      session.processing_status === 'completed' ? 'bg-green-500/20 text-green-400' :
                      session.processing_status === 'failed' ? 'bg-red-500/20 text-red-400' :
                      'bg-amber-500/20 text-amber-400'
                    }`}>
                      {session.processing_status}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm text-slate-300 font-mono">{session.processing_duration_ms}ms</td>
                  <td className="px-6 py-4 text-sm text-slate-400">
                    {new Date(session.upload_timestamp).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {sessions.length === 0 && (
          <div className="p-12 text-center">
            <p className="text-slate-400">No sessions yet. Upload a PCAP file to get started.</p>
          </div>
        )}
      </div>
    </div>
  );
}

import { healthApi } from '../services/api';