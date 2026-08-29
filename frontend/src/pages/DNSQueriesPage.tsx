import { useEffect, useState } from 'react';
import { Search, Filter, ChevronLeft, ChevronRight, Globe, Database } from 'lucide-react';
import { pcapApi } from '../services/api';
import type { DNSQueryList, AnalysisSession } from '../types';

export function DNSQueriesPage() {
  const [sessions, setSessions] = useState<AnalysisSession[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string>('');
  const [queries, setQueries] = useState<DNSQueryList['queries']>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [sessionsLoading, setSessionsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(50);
  const [search, setSearch] = useState('');
  const [filterType, setFilterType] = useState<'all' | 'query' | 'response'>('all');

  const fetchSessions = async () => {
    try {
      setSessionsLoading(true);
      const data = await pcapApi.getSessions(0, 100);
      setSessions(data.sessions);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load sessions');
    } finally {
      setSessionsLoading(false);
    }
  };

  const fetchQueries = async () => {
    if (!selectedSessionId) return;
    try {
      setLoading(true);
      setError(null);
      const sessionNum = parseInt(selectedSessionId, 10);
      const data = await pcapApi.getDNSQueries(sessionNum, (page - 1) * pageSize, pageSize);
      setQueries(data.queries);
      setTotal(data.total);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load queries');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSessions();
  }, []);

  useEffect(() => {
    if (selectedSessionId) {
      fetchQueries();
    } else {
      setQueries([]);
      setTotal(0);
    }
  }, [selectedSessionId, page, pageSize, filterType]);

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

  if (sessionsLoading) {
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
          <Database className="w-8 h-8" />
          DNS Queries
        </h1>
        <p className="text-slate-400">Monitor and search DNS traffic across all sessions</p>
      </div>

      <div className="bg-dark-card border border-dark-border rounded-xl overflow-hidden mb-8">
        <div className="p-4 border-b border-dark-border">
          <div className="flex flex-col lg:flex-row gap-4">
            <div className="flex-1 min-w-[250px]">
              <label className="block text-sm text-slate-400 mb-1">Select Session</label>
              <select
                value={selectedSessionId}
                onChange={(e) => { setSelectedSessionId(e.target.value); setPage(1); }}
                className="w-full px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white focus:outline-none focus:border-primary-500"
              >
                <option value="">-- Select a session --</option>
                {sessions.map((s) => (
                  <option key={s.id} value={String(s.id)}>
                    {s.original_filename} ({s.queries_extracted} queries)
                  </option>
                ))}
              </select>
            </div>
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
              className="px-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-white text-sm focus:outline-none focus:border-primary-500 w-40"
            >
              <option value="all">All Types</option>
              <option value="query">Queries Only</option>
              <option value="response">Responses Only</option>
            </select>
          </div>
        </div>

        {error && (
          <div className="p-4 border-b border-dark-border bg-red-500/5">
            <div className="flex items-center gap-3">
              <Globe className="w-5 h-5 text-red-400" />
              <p className="text-red-300">{error}</p>
            </div>
          </div>
        )}

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
              {filteredQueries.length === 0 && total === 0 && selectedSessionId ? (
                <tr>
                  <td colSpan={9} className="px-4 py-12 text-center text-slate-500">
                    No DNS queries found for this session
                  </td>
                </tr>
              ) : filteredQueries.length === 0 ? (
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

      {!selectedSessionId && (
        <div className="p-8 max-w-4xl mx-auto text-center">
          <Globe className="w-16 h-16 text-slate-700 mx-auto mb-4" />
          <h1 className="text-2xl font-bold text-white mb-2">No Session Selected</h1>
          <p className="text-slate-400 mb-6">Select a session from the dropdown above to view DNS queries</p>
        </div>
      )}
    </div>
  );
}