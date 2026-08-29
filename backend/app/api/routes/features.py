from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.dns.features import extract_features_for_session
from app.schemas.schemas import DNSFeaturesResponse
from app.services.database_service import get_session_by_uuid

router = APIRouter()


@router.get("/analysis/{session_uuid}/features", response_model=DNSFeaturesResponse)
async def get_analysis_features(
    session_uuid: str,
    db: Session = Depends(get_db),
):
    session = get_session_by_uuid(db, session_uuid)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    if session.processing_status != "completed":
        raise HTTPException(
            status_code=400,
            detail=f"Session is not ready for feature extraction (status: {session.processing_status})",
        )

    if session.queries_extracted == 0:
        return DNSFeaturesResponse(
            session_id=session_uuid,
            total_queries=0,
            group_count=0,
            groups=[],
        )

    groups = extract_features_for_session(db, session.id)
    return DNSFeaturesResponse(
        session_id=session_uuid,
        total_queries=session.queries_extracted,
        group_count=len(groups),
        groups=groups,
    )