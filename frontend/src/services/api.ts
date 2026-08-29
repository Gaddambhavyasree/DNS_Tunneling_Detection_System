import axios from 'axios';
import type { 
  DNSQueryList, 
  AnalysisSessionList, 
  AnalysisSession, 
  PCAPUploadResponse,
  HealthResponse,
  DetectionResultList,
  DetectionResultResponse,
  DetectionRunResponse,
  DetectionStatus,
  Alert,
  AlertList,
  AlertAcknowledgeRequest,
  DNSFeaturesResponse,
} from '../types';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

export const healthApi = {
  check: async (): Promise<HealthResponse> => {
    const response = await api.get('/health');
    return response.data;
  },
};

export const pcapApi = {
  upload: async (file: File): Promise<PCAPUploadResponse> => {
    const formData = new FormData();
    formData.append('file', file);
    
    const response = await api.post('/pcap/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  
  getSessions: async (skip = 0, limit = 100): Promise<AnalysisSessionList> => {
    const response = await api.get('/sessions', { params: { skip, limit } });
    return response.data;
  },
  
  getSession: async (sessionId: string): Promise<AnalysisSession> => {
    const response = await api.get(`/sessions/${sessionId}`);
    return response.data;
  },
  
  getDNSQueries: async (sessionId: number, skip = 0, limit = 100): Promise<DNSQueryList> => {
    const response = await api.get('/dns/queries', { params: { session_id: sessionId, skip, limit } });
    return response.data;
  },
};

export const detectionApi = {
  runDetection: async (sessionUuid: string): Promise<DetectionRunResponse> => {
    const response = await api.post(`/analysis/${sessionUuid}/detect`);
    return response.data;
  },
  
  getDetectionResults: async (sessionUuid: string): Promise<DetectionResultList> => {
    const response = await api.get(`/analysis/${sessionUuid}/detection`);
    return response.data;
  },
};

export const alertApi = {
  listAlerts: async (params?: {
    skip?: number;
    limit?: number;
    severity?: string;
    source_ip?: string;
    domain?: string;
    acknowledged?: boolean;
  }): Promise<AlertList> => {
    const response = await api.get('/alerts', { params });
    return response.data;
  },

  getAlert: async (alertId: number): Promise<Alert> => {
    const response = await api.get(`/alerts/${alertId}`);
    return response.data;
  },

  getAlertByUuid: async (alertUuid: string): Promise<Alert> => {
    const response = await api.get(`/alerts/uuid/${alertUuid}`);
    return response.data;
  },

  acknowledgeAlert: async (alertId: number, data: AlertAcknowledgeRequest): Promise<Alert> => {
    const response = await api.post(`/alerts/${alertId}/acknowledge`, data);
    return response.data;
  },
};

export const featuresApi = {
  getFeatures: async (sessionUuid: string): Promise<DNSFeaturesResponse> => {
    const response = await api.get(`/analysis/${sessionUuid}/features`);
    return response.data;
  },
};

export default api;