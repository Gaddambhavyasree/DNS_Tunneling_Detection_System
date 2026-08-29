export interface DNSQuery {
  id: number;
  session_id: number;
  timestamp: string;
  source_ip: string | null;
  destination_ip: string | null;
  transaction_id: number | null;
  query_name: string | null;
  query_type: number | null;
  query_type_name: string | null;
  response_code: number | null;
  response_code_name: string | null;
  answer_count: number;
  authority_count: number;
  additional_count: number;
  packet_size: number | null;
  is_query: boolean;
  source_file: string | null;
  created_at: string;
}

export interface DNSQueryList {
  queries: DNSQuery[];
  total: number;
  page: number;
  page_size: number;
}

export interface DNSFeaturesResponse {
  session_id: string;
  total_queries: number;
  group_count: number;
  groups: DNSGroupFeatureResponse[];
}

export interface DNSGroupFeatureResponse {
  source_ip: string;
  base_domain: string;
  query_count: number;
  unique_subdomain_count: number;
  queries_per_minute: number;
  peak_queries_per_minute: number;
  rate_ratio: number;
  txt_query_count: number;
  null_query_count: number;
  nxdomain_count: number;
  nxdomain_ratio: number;
  query_types: Record<string, number>;
  response_codes: Record<number, number>;
  query_timestamps: string[];
  queries: DNSQueryFeatureResponse[];
}

export interface DNSQueryFeatureResponse {
  source_ip: string | null;
  destination_ip: string | null;
  timestamp: string | null;
  query_name: string;
  normalized_name: string;
  query_type: number | null;
  query_type_name: string | null;
  response_code: number | null;
  response_code_name: string | null;
  is_query: boolean;
  is_null_query: boolean;
  is_nxdomain: boolean;
  is_txt_query: boolean;
  base_domain: string;
  subdomain: string;
  tld: string;
  label_count: number;
  query_name_length: number;
  longest_label_length: number;
  subdomain_length: number;
  entropy: number;
  encoding_types: string[];
}

export interface AnalysisSession {
  id: number;
  session_id: string;
  filename: string;
  original_filename: string;
  upload_timestamp: string;
  total_packets: number;
  dns_packets: number;
  queries_extracted: number;
  processing_status: 'pending' | 'processing' | 'completed' | 'failed';
  processing_duration_ms: number;
  error_message: string | null;
}

export interface AnalysisSessionList {
  sessions: AnalysisSession[];
  total: number;
}

export interface PCAPUploadResponse {
  session_id: string;
  filename: string;
  original_filename: string;
  total_packets: number;
  dns_packets: number;
  queries_extracted: number;
  processing_status: 'pending' | 'processing' | 'completed' | 'failed';
  processing_duration_ms: number;
  error_message: string | null;
}

export interface HealthResponse {
  status: string;
  version: string;
  database_connected: boolean;
}

export interface UploadProgress {
  session_id: string;
  status: 'pending' | 'processing' | 'completed' | 'failed';
  progress: number;
  message: string;
}

export type DetectionStatus = 'NORMAL' | 'SUSPICIOUS' | 'HIGH_RISK';

export interface DetectionIndicator {
  id: number;
  rule_id: string;
  indicator_name: string;
  description: string | null;
  threshold: number | null;
  observed_value: number | null;
  matched: boolean;
  severity: string | null;
  weight: number | null;
  explanation: string | null;
}

export interface DetectionResult {
  id: number;
  session_id: number;
  source_ip: string | null;
  base_domain: string | null;
  detection_status: DetectionStatus;
  total_queries: number;
  unique_subdomains: number;
  avg_label_length: number | null;
  max_label_length: number | null;
  avg_entropy: number | null;
  max_entropy: number | null;
  encoding_detected: boolean;
  encoding_types: string[] | null;
  queries_per_minute: number | null;
  txt_query_count: number;
  null_query_count: number;
  nxdomain_count: number;
  nxdomain_ratio: number | null;
  burst_detected: boolean;
  matched_rules_count: number;
  risk_score: number | null;
  created_at: string;
  indicators: DetectionIndicator[];
}

export interface DetectionResultList {
  results: DetectionResult[];
  total: number;
}

export interface DetectionRunResponse {
  success: boolean;
  message: string;
  results_count: number;
  results: DetectionResult[];
}

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Alert {
  id: number;
  alert_id: string;
  detection_result_id: number;
  source_ip: string | null;
  destination_ip: string | null;
  domain: string | null;
  normalized_domain: string | null;
  query_type: string | null;
  risk_score: number;
  severity: AlertSeverity;
  matched_rules: Record<string, any>[] | null;
  detection_reasons: Record<string, any>[] | null;
  observed_values: Record<string, any> | null;
  thresholds: Record<string, any> | null;
  rule_weights: Record<string, any> | null;
  created_at: string;
  acknowledged: boolean;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
}

export interface AlertList {
  alerts: Alert[];
  total: number;
}

export interface AlertAcknowledgeRequest {
  acknowledged_by: string;
}