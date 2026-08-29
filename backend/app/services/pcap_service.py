import os
import time
import logging
from pathlib import Path
from typing import Dict, Any

from sqlalchemy.orm import Session

from app.config import settings
from app.dns.parser import parse_pcap_file
from app.services.database_service import (
    create_session,
    update_session_completed,
    save_dns_queries,
    get_session_by_uuid,
)
from app.schemas.schemas import ProcessingStatus

logger = logging.getLogger(__name__)


def validate_pcap_file(filepath: Path) -> tuple[bool, str]:
    if not filepath.exists():
        return False, "File does not exist"
    
    if filepath.stat().st_size == 0:
        return False, "File is empty"
    
    if filepath.stat().st_size > settings.MAX_UPLOAD_SIZE:
        return False, f"File exceeds maximum size of {settings.MAX_UPLOAD_SIZE / (1024*1024)} MB"
    
    suffix = filepath.suffix.lower()
    if suffix not in settings.ALLOWED_EXTENSIONS:
        return False, f"Invalid file extension. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}"
    
    return True, ""


def process_pcap_file(db: Session, filepath: Path, original_filename: str) -> Dict[str, Any]:
    start_time = time.time()
    
    is_valid, error_msg = validate_pcap_file(filepath)
    if not is_valid:
        return {
            "success": False,
            "error": error_msg,
        }
    
    session = create_session(db, filepath.name, original_filename)
    
    try:
        stats = parse_pcap_file(str(filepath))
        
        saved_count = save_dns_queries(db, session.id, stats["dns_records"])
        
        processing_duration_ms = int((time.time() - start_time) * 1000)
        
        update_session_completed(
            db,
            session.id,
            total_packets=stats["total_packets"],
            dns_packets=stats["dns_packets"],
            queries_extracted=saved_count,
            processing_duration_ms=processing_duration_ms,
            status=ProcessingStatus.COMPLETED if not stats["errors"] else ProcessingStatus.COMPLETED,
            error_message="; ".join(stats["errors"]) if stats["errors"] else None,
        )
        
        return {
            "success": True,
            "session_id": session.session_id,
            "filename": session.filename,
            "original_filename": session.original_filename,
            "total_packets": stats["total_packets"],
            "dns_packets": stats["dns_packets"],
            "queries_extracted": saved_count,
            "processing_status": ProcessingStatus.COMPLETED,
            "processing_duration_ms": processing_duration_ms,
            "errors": stats["errors"],
        }
        
    except Exception as e:
        processing_duration_ms = int((time.time() - start_time) * 1000)
        logger.error(f"Error processing PCAP {filepath}: {e}", exc_info=True)
        
        update_session_completed(
            db,
            session.id,
            total_packets=0,
            dns_packets=0,
            queries_extracted=0,
            processing_duration_ms=processing_duration_ms,
            status=ProcessingStatus.FAILED,
            error_message=str(e),
        )
        
        return {
            "success": False,
            "error": str(e),
            "session_id": session.session_id,
        }


def get_session_results(db: Session, session_uuid: str) -> Dict[str, Any]:
    session = get_session_by_uuid(db, session_uuid)
    if not session:
        return {"success": False, "error": "Session not found"}
    
    return {
        "success": True,
        "session": session,
    }