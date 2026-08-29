from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Optional
import uuid

from app.models.models import AnalysisSession, DNSQuery
from app.schemas.schemas import ProcessingStatus


def create_session(
    db: Session,
    filename: str,
    original_filename: str,
) -> AnalysisSession:
    session = AnalysisSession(
        session_id=str(uuid.uuid4()),
        filename=filename,
        original_filename=original_filename,
        processing_status=ProcessingStatus.PROCESSING.value,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def update_session_completed(
    db: Session,
    session_id: int,
    total_packets: int,
    dns_packets: int,
    queries_extracted: int,
    processing_duration_ms: int,
    status: ProcessingStatus = ProcessingStatus.COMPLETED,
    error_message: Optional[str] = None,
) -> AnalysisSession:
    session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
    if session:
        session.total_packets = total_packets
        session.dns_packets = dns_packets
        session.queries_extracted = queries_extracted
        session.processing_duration_ms = processing_duration_ms
        session.processing_status = status.value
        session.error_message = error_message
        db.commit()
        db.refresh(session)
    return session


def get_session(db: Session, session_id: int) -> Optional[AnalysisSession]:
    return db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()


def get_session_by_uuid(db: Session, session_uuid: str) -> Optional[AnalysisSession]:
    return db.query(AnalysisSession).filter(AnalysisSession.session_id == session_uuid).first()


def list_sessions(db: Session, skip: int = 0, limit: int = 100) -> List[AnalysisSession]:
    return db.query(AnalysisSession).order_by(AnalysisSession.upload_timestamp.desc()).offset(skip).limit(limit).all()


def count_sessions(db: Session) -> int:
    return db.query(AnalysisSession).count()


def save_dns_queries(db: Session, session_id: int, dns_records: List[dict]) -> int:
    if not dns_records:
        return 0
    
    queries = []
    for record in dns_records:
        query = DNSQuery(
            session_id=session_id,
            timestamp=record["timestamp"],
            source_ip=record["source_ip"],
            destination_ip=record["destination_ip"],
            transaction_id=record["transaction_id"],
            query_name=record["query_name"],
            query_type=record["query_type"],
            query_type_name=record["query_type_name"],
            response_code=record["response_code"],
            response_code_name=record["response_code_name"],
            answer_count=record["answer_count"],
            authority_count=record["authority_count"],
            additional_count=record["additional_count"],
            packet_size=record["packet_size"],
            is_query=record["is_query"],
            source_file=record["source_file"],
        )
        queries.append(query)
    
    db.bulk_save_objects(queries)
    db.commit()
    return len(queries)


def get_dns_queries(
    db: Session,
    session_id: int,
    skip: int = 0,
    limit: int = 100,
) -> List[DNSQuery]:
    return (
        db.query(DNSQuery)
        .filter(DNSQuery.session_id == session_id)
        .order_by(DNSQuery.timestamp)
        .offset(skip)
        .limit(limit)
        .all()
    )


def count_dns_queries(db: Session, session_id: int) -> int:
    return db.query(DNSQuery).filter(DNSQuery.session_id == session_id).count()