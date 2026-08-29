import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { 
  Search, Filter, Download, ChevronLeft, ChevronRight, 
  Globe, Server, AlertCircle, CheckCircle, XCircle,
  BarChart2, Shield, Hash, Zap, Activity, Database
} from 'lucide-react';
import { pcapApi, featuresApi, detectionApi } from '../services/api';
import type { DNSQueryList, AnalysisSession, DNSFeaturesResponse } from '../types';
import { DetectionAnalysis } from '../components/DetectionAnalysis';

export function AnalysisPage() {
  const [searchParams] = useSearchParams();
  const sessionId = searchParams.get('session');
  
  const [session, setSession] = useState<AnalysisSession | null>(null);
  const [queries, setQueries] = useState<DNSQueryList['queries']>([]);
  const [total, setTotal] = useState(0);
  const [features, setFeatures] = useState<DNSFeaturesResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [featuresLoading, setFeaturesLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'query' | 'response'>('all');

  const fetchSession = async () => {
    if (!sessionId) return;
    try {
      const data = await pcapApi.getSession(sessionId);
      setSession(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load session');
    }
  };

  const fetchFeatures = async () => {
    if (!sessionId) return;
    try {
      setFeaturesLoading(true);
      const data = await featuresApi.getFeatures(sessionId);
      setFeatures(data);
    } catch (err: any) {
      console.warn('Failed to load features:', err);
    } finally {
      setFeaturesLoading(false);
    }
  };

  const fetchQueries = async () => {
    if (!sessionId) return;
    try {
      setLoading(true);
      const data = await pcapApi.getDNSQueries(parseInt(sessionId), (page - 1) * pageSize, pageSize);
      setQueries(data.queries);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load queries');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSession();
    fetchQueries();
    fetchFeatures();
  }, [sessionId]);

  useEffect(() => {
    if (sessionId) {
      fetchQueries();
    }
  }, [sessionId, page, pageSize, filterType]);

  const filteredQueries = queries.filter(q => {
    if (search && q.query_name && !q.query_name.toLowerCase().includes(search.toLowerCase())) {
      return false;
    }
    if (filterType === 'query' && !q.is_query) return false;
    if (filterType === 'response' && q.is_query) return false;
    return true;
  });

  const totalPages = Math.ceil(total / pageSize);

  const getTypeBadge = (q: DNSQueryList['queries'][0]) => {
    if (q.is_query) {
      return <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded">QUERY</span>;
    }
    const rcode = q.response_code_name || `RCODE ${q.response_code}`;
    const isError = q.response_code && q.response_code !== 0;
    return (
      <span className={`px-2 py-0.5 text-xs rounded ${isError ? 'bg-red-500/20 text-red-400' : 'bg-green-500/20 text-green-400'}`}>
        {rcode}
      </span>
    );
  };

  const getQueryTypeName = (q: DNSQueryList['queries'][0]) => {
    return q.query_type_name || (q.query_type ? `TYPE${q.query_type}` : 'UNKNOWN');
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

  if (loading && queries.length === 0) {
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

      {features && features.groups.length > 0 && (
        <div className="mb-8">
          <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-dark-border">
              <h2 className="text-lg font-medium text-white flex items-center gap-2">
                <BarChart2 className="w-5 h-5" />
                Extracted DNS Features ({features.group_count} group(s))
              </h2>
            </div>
            <div className="p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 mb-6">
                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                  <p className="text-slate-500 text-sm">Total Queries</p>
                  <p className="text-white font-mono text-2xl">{features.total_queries.toLocaleString()}</p>
                </div>
                <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-4">
                  <p className="text-slate-500 text-sm">Groups</p>
                  <p className="text-white font-mono text-2xl">{features.group_count}</p>
                </div>
              </div>

              <div className="space-y-6">
                {features.groups.map((group, idx) => (
                  <div key={idx} className="bg-slate-800/50 border border-slate-700 rounded-xl p-6">
                    <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 bg-primary-500/20 rounded-lg flex items-center justify-center">
                          <Server className="w-5 h-5 text-primary-400" />
                        </div>
                        <div>
                          <p className="font-mono text-sm text-primary-400">{group.source_ip}</p>
                          <p className="font-medium text-white">{group.base_domain}</p>
                        </div>
                      </div>
                      <span className="px-3 py-1 bg-slate-800 rounded-lg text-sm font-mono text-slate-300">
                        {group.query_count} queries
                      </span>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4 text-sm">
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">Unique Subdomains</p>
                        <p className="font-mono text-white text-xl">{group.unique_subdomain_count}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">Queries/Min</p>
                        <p className="font-mono text-white text-xl">{group.queries_per_minute.toFixed(1)}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">Peak Q/Min</p>
                        <p className="font-mono text-white text-xl">{group.peak_queries_per_minute.toFixed(1)}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">Rate Ratio</p>
                        <p className="font-mono text-white text-xl">{group.rate_ratio.toFixed(2)}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">TXT Queries</p>
                        <p className="font-mono text-white text-xl">{group.txt_query_count}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">NULL Queries</p>
                        <p className="font-mono text-white text-xl">{group.null_query_count}</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">NXDOMAIN</p>
                        <p className="font-mono text-white text-xl">{group.nxdomain_count} ({(group.nxdomain_ratio * 100).toFixed(1)}%)</p>
                      </div>
                      <div className="bg-slate-900/50 rounded-lg p-3">
                        <p className="text-slate-500 text-xs">Query Types</p>
                        <p className="font-mono text-white text-xs truncate">
                          {Object.entries(group.query_types).map(([k, v]) => `${k}:${v}`).join(', ')}
                        </p>
                      </div>
                    </div>

                    {group.queries.length > 0 && (
                      <div className="mt-4 pt-4 border-t border-slate-700">
                        <h4 className="text-sm font-medium text-slate-300 mb-3">Sample Queries</h4>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                          {group.queries.slice(0, 6).map((q, qIdx) => (
                            <div key={qIdx} className="bg-slate-900/50 rounded-lg p-3 text-xs">
                              <div className="flex items-center gap-2 mb-1">
                                <span className={q.is_query ? 'px-1.5 py-0.5 text-[10px] bg-blue-500/20 text-blue-400 rounded' : 'px-1.5 py-0.5 text-[10px] bg-purple-500/20 text-purple-400 rounded'}>
                                  {q.is_query ? 'Q' : 'R'}
                                </span>
                                <span className="text-slate-400 font-mono">{q.query_type_name || `TYPE${q.query_type}`}</span>
                              </div>
                              <p className="font-mono text-white truncate">{q.query_name}</p>
                              <div className="flex items-center gap-3 mt-1 text-slate-500">
                                <span>Entropy: <span className="text-slate-300 font-mono">{q.entropy.toFixed(2)}</span></span>
                                <span>Enc: <span className="text-slate-300 font-mono">{q.encoding_types.join(', ') || 'None'}</span></span>
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
        </div>
      )}

      {sessionId && session?.processing_status === 'completed' && (
        <div className="mb-8">
          <DetectionAnalysis sessionUuid={sessionId} />
        </div>
      )}

      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden">
        <div className="p-4 border-b border-dark-border flex flex-col sm:flex-row gap-4 items-start sm:items-center justify-between">
          <h2 className="text-lg font-medium text-white">DNS Queries ({total.toLocaleString()})</h2>
          <div className="flex flex-col sm:flex-row gap-3 w-full sm:w-auto">
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search query names..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(1); }}
                className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:border-primary-500 text-sm"
              />
            </div>
            <select
              value={filterType}
              onChange={(e) => { setFilterType(e.target.value as any); setPage(1); }}
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500"
            >
              <option value="all">All Types</option>
              <option value="query">Queries Only</option>
              <option value="response">Responses Only</option>
            </select>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-dark-border bg-slate-800/50">
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Time</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Source IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Dest IP</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Type</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Query Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">QType</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">RCode</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Answers</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-slate-400 uppercase tracking-wider">Size</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {filteredQueries.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-slate-500">
                    No DNS queries match the current filters
                  </td>
                </tr>
              ) : (
                filteredQueries.map((q) => (
                  <tr key={q.id} className="hover:bg-slate-800/50 transition-colors">
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                      {new Date(q.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                      {q.source_ip || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                      {q.destination_ip || '—'}
                    </td>
                    <td className="px-4 py-3">
                      {q.is_query ? (
                        <span className="px-2 py-0.5 text-xs bg-blue-500/20 text-blue-400 rounded">Q</span>
                      ) : (
                        <span className="px-2 py-0.5 text-xs bg-purple-500/20 text-purple-400 rounded">R</span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono truncate max-w-xs" title={q.query_name || ''}>
                      {q.query_name || '—'}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                      {getQueryTypeName(q)}
                    </td>
                    <td className="px-4 py-3">
                      {getTypeBadge(q)}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-300 font-mono">
                      {q.answer_count}
                    </td>
                    <td className="px-4 py-3 text-xs text-slate-400 font-mono">
                      {q.packet_size ? `${q.packet_size}B` : '—'}
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
                disabled={page === 1}
                className="px-3 py-1 text-sm bg-slate-800 border border-slate-700 rounded hover:bg-slate-700 disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
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