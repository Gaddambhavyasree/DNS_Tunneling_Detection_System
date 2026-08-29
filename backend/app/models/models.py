from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Float, Boolean, Index, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from app.database.database import Base


class AnalysisSession(Base):
    __tablename__ = "analysis_sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(64), unique=True, index=True, nullable=False)
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    upload_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    total_packets = Column(Integer, default=0, nullable=False)
    dns_packets = Column(Integer, default=0, nullable=False)
    queries_extracted = Column(Integer, default=0, nullable=False)
    processing_status = Column(String(50), default="pending", nullable=False)
    processing_duration_ms = Column(Integer, default=0, nullable=False)
    error_message = Column(Text, nullable=True)

    dns_queries = relationship("DNSQuery", back_populates="session", cascade="all, delete-orphan")
    detection_results = relationship("DetectionResult", back_populates="session", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_session_upload_timestamp", "upload_timestamp"),
        Index("ix_session_processing_status", "processing_status"),
    )


class DNSQuery(Base):
    __tablename__ = "dns_queries"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("analysis_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True, index=True)
    transaction_id = Column(Integer, nullable=True)
    query_name = Column(String(255), nullable=True, index=True)
    query_type = Column(Integer, nullable=True)
    query_type_name = Column(String(20), nullable=True)
    response_code = Column(Integer, nullable=True)
    response_code_name = Column(String(20), nullable=True)
    answer_count = Column(Integer, default=0, nullable=False)
    authority_count = Column(Integer, default=0, nullable=False)
    additional_count = Column(Integer, default=0, nullable=False)
    packet_size = Column(Integer, nullable=True)
    is_query = Column(Boolean, default=True, nullable=False)
    source_file = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    session = relationship("AnalysisSession", back_populates="dns_queries")

    __table_args__ = (
        Index("ix_dns_query_timestamp", "timestamp"),
        Index("ix_dns_query_source_ip", "source_ip"),
        Index("ix_dns_query_query_name", "query_name"),
        Index("ix_dns_query_session_timestamp", "session_id", "timestamp"),
    )


class DetectionResult(Base):
    __tablename__ = "detection_results"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, ForeignKey("analysis_sessions.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    base_domain = Column(String(255), nullable=True, index=True)
    detection_status = Column(String(20), nullable=False)
    total_queries = Column(Integer, default=0, nullable=False)
    unique_subdomains = Column(Integer, default=0, nullable=False)
    avg_label_length = Column(Float, nullable=True)
    max_label_length = Column(Integer, nullable=True)
    avg_entropy = Column(Float, nullable=True)
    max_entropy = Column(Float, nullable=True)
    encoding_detected = Column(Boolean, default=False, nullable=False)
    encoding_types = Column(JSON, nullable=True)
    queries_per_minute = Column(Float, nullable=True)
    txt_query_count = Column(Integer, default=0, nullable=False)
    null_query_count = Column(Integer, default=0, nullable=False)
    nxdomain_count = Column(Integer, default=0, nullable=False)
    nxdomain_ratio = Column(Float, nullable=True)
    burst_detected = Column(Boolean, default=False, nullable=False)
    matched_rules_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    session = relationship("AnalysisSession", back_populates="detection_results")
    indicators = relationship("DetectionIndicator", back_populates="detection_result", cascade="all, delete-orphan")
    alerts = relationship("Alert", back_populates="detection_result", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_detection_session_source", "session_id", "source_ip"),
        Index("ix_detection_status", "detection_status"),
    )


class DetectionIndicator(Base):
    __tablename__ = "detection_indicators"

    id = Column(Integer, primary_key=True, index=True)
    detection_result_id = Column(Integer, ForeignKey("detection_results.id", ondelete="CASCADE"), nullable=False, index=True)
    rule_id = Column(String(20), nullable=False)
    indicator_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    threshold = Column(Float, nullable=True)
    observed_value = Column(Float, nullable=True)
    matched = Column(Boolean, default=False, nullable=False)
    severity = Column(String(20), nullable=True)
    weight = Column(Float, nullable=True)
    explanation = Column(Text, nullable=True)

    detection_result = relationship("DetectionResult", back_populates="indicators")

    __table_args__ = (
        Index("ix_indicator_detection_result", "detection_result_id"),
        Index("ix_indicator_rule_id", "rule_id"),
    )


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(64), unique=True, index=True, nullable=False)
    detection_result_id = Column(Integer, ForeignKey("detection_results.id", ondelete="CASCADE"), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    normalized_domain = Column(String(255), nullable=True)
    query_type = Column(String(20), nullable=True)
    risk_score = Column(Integer, nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    matched_rules = Column(JSON, nullable=True)
    detection_reasons = Column(JSON, nullable=True)
    observed_values = Column(JSON, nullable=True)
    thresholds = Column(JSON, nullable=True)
    rule_weights = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    acknowledged = Column(Boolean, default=False, nullable=False)
    acknowledged_at = Column(DateTime, nullable=True)
    acknowledged_by = Column(String(100), nullable=True)

    detection_result = relationship("DetectionResult", back_populates="alerts")

    __table_args__ = (
        Index("ix_alert_severity_created", "severity", "created_at"),
        Index("ix_alert_source_domain", "source_ip", "domain"),
        Index("ix_alert_acknowledged", "acknowledged"),
    )