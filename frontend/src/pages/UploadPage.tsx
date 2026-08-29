import { useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText, Loader2, CheckCircle, AlertCircle, ChevronRight } from 'lucide-react';
import { pcapApi } from '../services/api';
import type { PCAPUploadResponse } from '../types';

export function UploadPage() {
  const navigate = useNavigate();
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [progress, setProgress] = useState<{ stage: string; percent: number } | null>(null);
  const [result, setResult] = useState<PCAPUploadResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);

  const validateFile = useCallback((f: File): boolean => {
    const allowedExtensions = ['.pcap', '.pcapng'];
    const ext = '.' + f.name.split('.').pop()?.toLowerCase();
    
    if (!allowedExtensions.includes(ext)) {
      setError(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
      return false;
    }
    
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (f.size > maxSize) {
      setError('File size exceeds 100MB limit');
      return false;
    }
    
    return true;
  }, []);

  const handleFileSelect = useCallback((f: File) => {
    setError(null);
    setResult(null);
    if (validateFile(f)) {
      setFile(f);
    }
  }, [validateFile]);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileSelect(e.dataTransfer.files[0]);
    }
  }, [handleFileSelect]);

  const handleUpload = async () => {
    if (!file) return;
    
    setUploading(true);
    setError(null);
    setResult(null);
    setProgress({ stage: 'Uploading...', percent: 10 });
    
    try {
      setProgress({ stage: 'Processing PCAP...', percent: 30 });
      const response = await pcapApi.upload(file);
      setProgress({ stage: 'Complete', percent: 100 });
      setResult(response);
      
      if (response.processing_status === 'completed') {
        setTimeout(() => {
          navigate(`/analysis?session=${response.session_id}`);
        }, 1500);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || 'Upload failed');
      setProgress(null);
    } finally {
      setUploading(false);
    }
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-white mb-2">Upload PCAP/PCAPNG</h1>
        <p className="text-slate-400">Upload a packet capture file to extract and analyze DNS traffic</p>
      </div>

      <div className="bg-dark-card border border-dark-border rounded-xl p-6">
        <div
          className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
            dragActive 
              ? 'border-primary-500 bg-primary-500/5' 
              : 'border-slate-700 hover:border-slate-500'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <input
            type="file"
            id="pcap-file"
            accept=".pcap,.pcapng"
            className="hidden"
            onChange={(e) => e.target.files?.[0] && handleFileSelect(e.target.files[0])}
            disabled={uploading}
          />
          
          <label htmlFor="pcap-file" className="cursor-pointer">
            <FileText className="w-16 h-16 mx-auto text-slate-500 mb-4" />
            <p className="text-lg text-slate-300 mb-1">Drag & drop a PCAP/PCAPNG file here</p>
            <p className="text-sm text-slate-500">or click to browse</p>
            <p className="text-xs text-slate-600 mt-2">Max size: 100MB</p>
          </label>
        </div>

        {file && (
          <div className="mt-6 p-4 bg-slate-800/50 rounded-lg border border-slate-700">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <FileText className="w-8 h-8 text-primary-500" />
                <div>
                  <p className="font-medium text-white">{file.name}</p>
                  <p className="text-sm text-slate-400">{formatFileSize(file.size)}</p>
                </div>
              </div>
              <button
                onClick={() => { setFile(null); setError(null); setResult(null); }}
                className="text-slate-400 hover:text-red-400 transition-colors"
              >
                ✕
              </button>
            </div>
          </div>
        )}

        {error && (
          <div className="mt-6 p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-center gap-3">
            <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
            <p className="text-red-300">{error}</p>
          </div>
        )}

        {uploading && progress && (
          <div className="mt-6">
            <div className="flex items-center justify-between mb-2">
              <span className="text-slate-300">{progress.stage}</span>
              <span className="text-primary-400 font-mono">{progress.percent}%</span>
            </div>
            <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-primary-500 transition-all duration-300"
                style={{ width: `${progress.percent}%` }}
              />
            </div>
            <Loader2 className="w-5 h-5 text-primary-500 animate-spin mt-2 mx-auto" />
          </div>
        )}

        {result && !uploading && (
          <div className="mt-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg">
            <div className="flex items-center gap-3 mb-4">
              <CheckCircle className="w-6 h-6 text-green-400" />
              <h3 className="text-lg font-medium text-green-300">Processing Complete</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <p className="text-slate-500">Total Packets</p>
                <p className="text-white font-mono text-xl">{result.total_packets}</p>
              </div>
              <div>
                <p className="text-slate-500">DNS Packets</p>
                <p className="text-white font-mono text-xl">{result.dns_packets}</p>
              </div>
              <div>
                <p className="text-slate-500">Queries Extracted</p>
                <p className="text-white font-mono text-xl">{result.queries_extracted}</p>
              </div>
              <div>
                <p className="text-slate-500">Duration</p>
                <p className="text-white font-mono text-xl">{result.processing_duration_ms}ms</p>
              </div>
            </div>
            
            {result.errors && result.errors.length > 0 && (
              <div className="mt-4 p-3 bg-amber-500/10 border border-amber-500/30 rounded-lg">
                <p className="text-amber-300 text-sm mb-2">Warnings:</p>
                <ul className="text-amber-200 text-xs space-y-1">
                  {result.errors.map((err, i) => (
                    <li key={i}>• {err}</li>
                  ))}
                </ul>
              </div>
            )}

            {result.queries_extracted > 0 && (
              <button
                onClick={() => navigate(`/analysis?session=${result.session_id}`)}
                className="mt-6 w-full py-3 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg flex items-center justify-center gap-2 transition-colors"
              >
                View Analysis
                <ChevronRight className="w-5 h-5" />
              </button>
            )}
          </div>
        )}

        {!uploading && file && !result && (
          <button
            onClick={handleUpload}
            className="mt-6 w-full py-3 bg-primary-600 hover:bg-primary-700 text-white font-medium rounded-lg transition-colors"
            disabled={uploading}
          >
            Upload & Analyze
          </button>
        )}
      </div>

      <div className="mt-8 p-6 bg-dark-card border border-dark-border rounded-xl">
        <h3 className="text-lg font-medium text-white mb-4">How to Capture DNS Traffic</h3>
        <ol className="space-y-3 text-sm text-slate-300">
          <li className="flex gap-3">
            <span className="w-6 h-6 bg-primary-500/20 text-primary-400 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">1</span>
            <span>Open Wireshark and select your network interface</span>
          </li>
          <li className="flex gap-3">
            <span className="w-6 h-6 bg-primary-500/20 text-primary-400 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">2</span>
            <span>Start capture with display filter: <code className="bg-slate-800 px-1.5 py-0.5 rounded text-primary-400 font-mono text-xs">dns</code></span>
          </li>
          <li className="flex gap-3">
            <span className="w-6 h-6 bg-primary-500/20 text-primary-400 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">3</span>
            <span>Generate normal DNS traffic (browse websites, run nslookup/dig)</span>
          </li>
          <li className="flex gap-3">
            <span className="w-6 h-6 bg-primary-500/20 text-primary-400 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">4</span>
            <span>Stop capture and save as <code className="bg-slate-800 px-1.5 py-0.5 rounded text-primary-400 font-mono text-xs">.pcapng</code></span>
          </li>
          <li className="flex gap-3">
            <span className="w-6 h-6 bg-primary-500/20 text-primary-400 rounded-full flex items-center justify-center text-xs font-medium flex-shrink-0">5</span>
            <span>Upload the file here for analysis</span>
          </li>
        </ol>
      </div>
    </div>
  );
}