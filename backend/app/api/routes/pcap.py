from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.orm import Session
from typing import List
import uuid
import os
from pathlib import Path

from app.database.database import get_db
from app.services.pcap_service import process_pcap_file, get_session_results
from app.services.database_service import list_sessions, count_sessions, get_dns_queries, count_dns_queries
from app.schemas.schemas import (
    PCAPUploadResponse,
    AnalysisSessionList,
    AnalysisSessionResponse,
    DNSQueryList,
    DNSQueryResponse,
    ErrorResponse,
    ProcessingStatus,
)
from app.config import settings

router = APIRouter()


def save_upload_file(upload_file: UploadFile) -> Path:
    unique_filename = f"{uuid.uuid4()}{Path(upload_file.filename).suffix}"
    filepath = settings.UPLOAD_DIR / unique_filename
    
    with open(filepath, "wb") as buffer:
        content = upload_file.file.read()
        buffer.write(content)
    
    return filepath


@router.post("/pcap/upload", response_model=PCAPUploadResponse)
async def upload_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")
    
    suffix = Path(file.filename).suffix.lower()
    if suffix not in settings.ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file extension. Allowed: {', '.join(settings.ALLOWED_EXTENSIONS)}"
        )
    
    filepath = save_upload_file(file)
    
    try:
        result = process_pcap_file(db, filepath, file.filename)
        
        if not result["success"]:
            if filepath.exists():
                filepath.unlink()
            raise HTTPException(status_code=500, detail=result.get("error", "Processing failed"))
        
        return PCAPUploadResponse(
            session_id=result["session_id"],
            filename=result["filename"],
            original_filename=result["original_filename"],
            total_packets=result["total_packets"],
            dns_packets=result["dns_packets"],
            queries_extracted=result["queries_extracted"],
            processing_status=result["processing_status"],
            processing_duration_ms=result["processing_duration_ms"],
            error_message=result.get("error"),
        )
        
    except HTTPException:
        raise
    except Exception as e:
        if filepath.exists():
            filepath.unlink()
        raise HTTPException(status_code=500, detail=f"Upload processing failed: {str(e)}")


@router.get("/sessions", response_model=AnalysisSessionList)
async def get_sessions(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    sessions = list_sessions(db, skip=skip, limit=limit)
    total = count_sessions(db)
    
    return AnalysisSessionList(
        sessions=[
            AnalysisSessionResponse(
                id=s.id,
                session_id=s.session_id,
                filename=s.filename,
                original_filename=s.original_filename,
                upload_timestamp=s.upload_timestamp,
                total_packets=s.total_packets,
                dns_packets=s.dns_packets,
                queries_extracted=s.queries_extracted,
                processing_status=ProcessingStatus(s.processing_status),
                processing_duration_ms=s.processing_duration_ms,
                error_message=s.error_message,
            )
            for s in sessions
        ],
        total=total,
    )


@router.get("/sessions/{session_id}", response_model=AnalysisSessionResponse)
async def get_session(
    session_id: str,
    db: Session = Depends(get_db),
):
    result = get_session_results(db, session_id)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["error"])
    
    session = result["session"]
    return AnalysisSessionResponse(
        id=session.id,
        session_id=session.session_id,
        filename=session.filename,
        original_filename=session.original_filename,
        upload_timestamp=session.upload_timestamp,
        total_packets=session.total_packets,
        dns_packets=session.dns_packets,
        queries_extracted=session.queries_extracted,
        processing_status=ProcessingStatus(session.processing_status),
        processing_duration_ms=session.processing_duration_ms,
        error_message=session.error_message,
    )


@router.get("/dns/queries", response_model=DNSQueryList)
async def get_dns_queries_list(
    session_id: int = Query(...),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    queries = get_dns_queries(db, session_id, skip=skip, limit=limit)
    total = count_dns_queries(db, session_id)
    
    return DNSQueryList(
        queries=[
            DNSQueryResponse(
                id=q.id,
                session_id=q.session_id,
                timestamp=q.timestamp,
                source_ip=q.source_ip,
                destination_ip=q.destination_ip,
                transaction_id=q.transaction_id,
                query_name=q.query_name,
                query_type=q.query_type,
                query_type_name=q.query_type_name,
                response_code=q.response_code,
                response_code_name=q.response_code_name,
                answer_count=q.answer_count,
                authority_count=q.authority_count,
                additional_count=q.additional_count,
                packet_size=q.packet_size,
                is_query=q.is_query,
                source_file=q.source_file,
                created_at=q.created_at,
            )
            for q in queries
        ],
        total=total,
        page=skip // limit + 1,
        page_size=limit,
    )