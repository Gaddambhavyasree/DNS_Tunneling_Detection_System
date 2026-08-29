from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict
from enum import Enum


class ProcessingStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class DetectionStatus(str, Enum):
    PENDING = "PENDING"
    NORMAL = "NORMAL"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"


class PCAPUploadResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    filename: str
    original_filename: str
    total_packets: int
    dns_packets: int
    queries_extracted: int
    processing_status: ProcessingStatus
    processing_duration_ms: int
    error_message: Optional[str] = None


class AnalysisSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: str
    filename: str
    original_filename: str
    upload_timestamp: datetime
    total_packets: int
    dns_packets: int
    queries_extracted: int
    processing_status: ProcessingStatus
    processing_duration_ms: int
    error_message: Optional[str] = None


class AnalysisSessionList(BaseModel):
    sessions: List[AnalysisSessionResponse]
    total: int


class DNSQueryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: int
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    transaction_id: Optional[int] = None
    query_name: Optional[str] = None
    query_type: Optional[int] = None
    query_type_name: Optional[str] = None
    response_code: Optional[int] = None
    response_code_name: Optional[str] = None
    answer_count: int
    authority_count: int
    additional_count: int
    packet_size: Optional[int] = None
    is_query: bool
    source_file: Optional[str] = None
    created_at: datetime


class DNSQueryList(BaseModel):
    queries: List[DNSQueryResponse]
    total: int
    page: int
    page_size: int


class DetectionIndicatorResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    rule_id: str
    indicator_name: str
    description: Optional[str] = None
    threshold: Optional[float] = None
    observed_value: Optional[float] = None
    matched: bool
    severity: Optional[str] = None
    weight: Optional[float] = None
    explanation: Optional[str] = None


class DetectionResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    session_id: int
    source_ip: Optional[str] = None
    base_domain: Optional[str] = None
    detection_status: DetectionStatus
    total_queries: int
    unique_subdomains: int
    avg_label_length: Optional[float] = None
    max_label_length: Optional[int] = None
    avg_entropy: Optional[float] = None
    max_entropy: Optional[float] = None
    encoding_detected: bool
    encoding_types: Optional[List[str]] = None
    queries_per_minute: Optional[float] = None
    txt_query_count: int
    null_query_count: int
    nxdomain_count: int
    nxdomain_ratio: Optional[float] = None
    burst_detected: bool
    matched_rules_count: int
    risk_score: Optional[float] = None
    created_at: datetime
    indicators: List[DetectionIndicatorResponse] = []


class DetectionResultList(BaseModel):
    results: List[DetectionResultResponse]
    total: int


class DetectionRunResponse(BaseModel):
    success: bool
    message: str
    results_count: int
    results: List[DetectionResultResponse] = []


class HealthResponse(BaseModel):
    status: str
    version: str
    database_connected: bool


class ErrorResponse(BaseModel):
    detail: str
    error_code: Optional[str] = None


class UploadProgress(BaseModel):
    session_id: str
    status: ProcessingStatus
    progress: int
    message: str


class ParsedDomainResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    query_name: str
    normalized_name: str
    base_domain: str
    subdomain: str
    tld: str
    label_count: int
    query_name_length: int
    longest_label_length: int
    subdomain_length: int


class DNSQueryFeatureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    timestamp: Optional[datetime] = None
    query_name: str
    normalized_name: str
    query_type: Optional[int] = None
    query_type_name: Optional[str] = None
    response_code: Optional[int] = None
    response_code_name: Optional[str] = None
    is_query: bool
    is_null_query: bool
    is_nxdomain: bool
    is_txt_query: bool
    base_domain: str
    subdomain: str
    tld: str
    label_count: int
    query_name_length: int
    longest_label_length: int
    subdomain_length: int
    entropy: float
    encoding_types: List[str] = []


class DNSGroupFeatureResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    source_ip: str
    base_domain: str
    query_count: int
    unique_subdomain_count: int
    queries_per_minute: float
    peak_queries_per_minute: float
    rate_ratio: float
    txt_query_count: int
    null_query_count: int
    nxdomain_count: int
    nxdomain_ratio: float
    query_types: Dict[str, int] = {}
    response_codes: Dict[int, int] = {}
    query_timestamps: List[datetime] = []
    queries: List[DNSQueryFeatureResponse] = []


class DNSFeaturesResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    session_id: str
    total_queries: int
    group_count: int
    groups: List[DNSGroupFeatureResponse] = []


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    alert_id: str
    detection_result_id: int
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    domain: Optional[str] = None
    normalized_domain: Optional[str] = None
    query_type: Optional[str] = None
    risk_score: int
    severity: AlertSeverity
    matched_rules: Optional[List[Dict]] = None
    detection_reasons: Optional[List[Dict]] = None
    observed_values: Optional[Dict] = None
    thresholds: Optional[Dict] = None
    rule_weights: Optional[Dict] = None
    created_at: datetime
    acknowledged: bool
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None


class AlertList(BaseModel):
    alerts: List[AlertResponse]
    total: int


class AlertAcknowledgeRequest(BaseModel):
    acknowledged_by: str