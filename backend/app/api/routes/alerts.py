from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional

from app.database.database import get_db
from app.schemas.schemas import (
    AlertList,
    AlertResponse,
    AlertSeverity,
    AlertAcknowledgeRequest,
)
from app.dns.alert_service import AlertService
from app.models.models import Alert

router = APIRouter()


@router.get("/alerts", response_model=AlertList)
async def list_alerts(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    domain: Optional[str] = Query(None),
    acknowledged: Optional[bool] = Query(None),
    db: Session = Depends(get_db),
):
    service = AlertService()
    
    alerts = service.list_alerts(
        db,
        skip=skip,
        limit=limit,
        severity=severity,
        source_ip=source_ip,
        domain=domain,
        acknowledged=acknowledged,
    )
    
    total = service.count_alerts(
        db,
        severity=severity,
        source_ip=source_ip,
        domain=domain,
        acknowledged=acknowledged,
    )
    
    alert_responses = []
    for a in alerts:
        alert_responses.append(
            AlertResponse(
                id=a.id,
                alert_id=a.alert_id,
                detection_result_id=a.detection_result_id,
                source_ip=a.source_ip,
                destination_ip=a.destination_ip,
                domain=a.domain,
                normalized_domain=a.normalized_domain,
                query_type=a.query_type,
                risk_score=a.risk_score,
                severity=AlertSeverity(a.severity),
                matched_rules=a.matched_rules,
                detection_reasons=a.detection_reasons,
                observed_values=a.observed_values,
                thresholds=a.thresholds,
                rule_weights=a.rule_weights,
                created_at=a.created_at,
                acknowledged=a.acknowledged,
                acknowledged_at=a.acknowledged_at,
                acknowledged_by=a.acknowledged_by,
            )
        )
    
    return AlertList(alerts=alert_responses, total=total)


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
):
    service = AlertService()
    alert = service.get_alert(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse(
        id=alert.id,
        alert_id=alert.alert_id,
        detection_result_id=alert.detection_result_id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        domain=alert.domain,
        normalized_domain=alert.normalized_domain,
        query_type=alert.query_type,
        risk_score=alert.risk_score,
        severity=AlertSeverity(alert.severity),
        matched_rules=alert.matched_rules,
        detection_reasons=alert.detection_reasons,
        observed_values=alert.observed_values,
        thresholds=alert.thresholds,
        rule_weights=alert.rule_weights,
        created_at=alert.created_at,
        acknowledged=alert.acknowledged,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by,
    )


@router.get("/alerts/uuid/{alert_uuid}", response_model=AlertResponse)
async def get_alert_by_uuid(
    alert_uuid: str,
    db: Session = Depends(get_db),
):
    service = AlertService()
    alert = service.get_alert_by_uuid(db, alert_uuid)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse(
        id=alert.id,
        alert_id=alert.alert_id,
        detection_result_id=alert.detection_result_id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        domain=alert.domain,
        normalized_domain=alert.normalized_domain,
        query_type=alert.query_type,
        risk_score=alert.risk_score,
        severity=AlertSeverity(alert.severity),
        matched_rules=alert.matched_rules,
        detection_reasons=alert.detection_reasons,
        observed_values=alert.observed_values,
        thresholds=alert.thresholds,
        rule_weights=alert.rule_weights,
        created_at=alert.created_at,
        acknowledged=alert.acknowledged,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by,
    )


@router.post("/alerts/{alert_id}/acknowledge", response_model=AlertResponse)
async def acknowledge_alert(
    alert_id: int,
    request: AlertAcknowledgeRequest,
    db: Session = Depends(get_db),
):
    service = AlertService()
    alert = service.acknowledge_alert(db, alert_id, request.acknowledged_by)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return AlertResponse(
        id=alert.id,
        alert_id=alert.alert_id,
        detection_result_id=alert.detection_result_id,
        source_ip=alert.source_ip,
        destination_ip=alert.destination_ip,
        domain=alert.domain,
        normalized_domain=alert.normalized_domain,
        query_type=alert.query_type,
        risk_score=alert.risk_score,
        severity=AlertSeverity(alert.severity),
        matched_rules=alert.matched_rules,
        detection_reasons=alert.detection_reasons,
        observed_values=alert.observed_values,
        thresholds=alert.thresholds,
        rule_weights=alert.rule_weights,
        created_at=alert.created_at,
        acknowledged=alert.acknowledged,
        acknowledged_at=alert.acknowledged_at,
        acknowledged_by=alert.acknowledged_by,
    )