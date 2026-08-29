from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List

from app.database.database import get_db
from app.schemas.schemas import (
    DetectionResultList,
    DetectionResultResponse,
    DetectionRunResponse,
    DetectionStatus,
)
from app.dns.detection import run_detection_for_session, get_detection_results_for_session
from app.services.database_service import get_session_by_uuid

router = APIRouter()


@router.post("/analysis/{session_uuid}/detect", response_model=DetectionRunResponse)
async def run_detection(
    session_uuid: str,
    db: Session = Depends(get_db),
):
    session = get_session_by_uuid(db, session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    if session.processing_status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Session is not ready for detection (status: {session.processing_status})",
        )
    
    if session.queries_extracted == 0:
        return DetectionRunResponse(
            success=True,
            message="No DNS queries to analyze",
            results_count=0,
            results=[],
        )
    
    try:
        results = run_detection_for_session(db, session.id)
        
        result_responses = []
        for r in results:
            indicators = [
                {
                    "id": ind.id,
                    "rule_id": ind.rule_id,
                    "indicator_name": ind.indicator_name,
                    "description": ind.description,
                    "threshold": ind.threshold,
                    "observed_value": ind.observed_value,
                    "matched": ind.matched,
                    "severity": ind.severity,
                    "weight": ind.weight,
                    "explanation": ind.explanation,
                }
                for ind in r.indicators
            ]
            
            result_responses.append(
                DetectionResultResponse(
                    id=r.id,
                    session_id=r.session_id,
                    source_ip=r.source_ip,
                    base_domain=r.base_domain,
                    detection_status=DetectionStatus(r.detection_status),
                    total_queries=r.total_queries,
                    unique_subdomains=r.unique_subdomains,
                    avg_label_length=r.avg_label_length,
                    max_label_length=r.max_label_length,
                    avg_entropy=r.avg_entropy,
                    max_entropy=r.max_entropy,
                    encoding_detected=r.encoding_detected,
                    encoding_types=r.encoding_types,
                    queries_per_minute=r.queries_per_minute,
                    txt_query_count=r.txt_query_count,
                    null_query_count=r.null_query_count,
                    nxdomain_count=r.nxdomain_count,
                    nxdomain_ratio=r.nxdomain_ratio,
                    burst_detected=r.burst_detected,
                    matched_rules_count=r.matched_rules_count,
                    risk_score=r.risk_score,
                    created_at=r.created_at,
                    indicators=indicators,
                )
            )
        
        return DetectionRunResponse(
            success=True,
            message=f"Detection completed. Found {len(results)} activity group(s).",
            results_count=len(results),
            results=result_responses,
        )
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.get("/analysis/{session_uuid}/detection", response_model=DetectionResultList)
async def get_detection_results(
    session_uuid: str,
    db: Session = Depends(get_db),
):
    session = get_session_by_uuid(db, session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    
    results = get_detection_results_for_session(db, session.id)
    
    result_responses = []
    for r in results:
        indicators = [
            {
                "id": ind.id,
                "rule_id": ind.rule_id,
                "indicator_name": ind.indicator_name,
                "description": ind.description,
                "threshold": ind.threshold,
                "observed_value": ind.observed_value,
                "matched": ind.matched,
                "severity": ind.severity,
                "weight": ind.weight,
                "explanation": ind.explanation,
            }
            for ind in r.indicators
        ]
        
        result_responses.append(
            DetectionResultResponse(
                id=r.id,
                session_id=r.session_id,
                source_ip=r.source_ip,
                base_domain=r.base_domain,
                detection_status=DetectionStatus(r.detection_status),
                total_queries=r.total_queries,
                unique_subdomains=r.unique_subdomains,
                avg_label_length=r.avg_label_length,
                max_label_length=r.max_label_length,
                avg_entropy=r.avg_entropy,
                max_entropy=r.max_entropy,
                encoding_detected=r.encoding_detected,
                encoding_types=r.encoding_types,
                queries_per_minute=r.queries_per_minute,
                txt_query_count=r.txt_query_count,
                null_query_count=r.null_query_count,
                nxdomain_count=r.nxdomain_count,
                nxdomain_ratio=r.nxdomain_ratio,
                burst_detected=r.burst_detected,
                matched_rules_count=r.matched_rules_count,
                risk_score=r.risk_score,
                created_at=r.created_at,
                indicators=indicators,
            )
        )
    
    return DetectionResultList(
        results=result_responses,
        total=len(result_responses),
    )