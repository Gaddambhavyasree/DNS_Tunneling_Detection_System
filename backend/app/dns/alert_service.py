import json
import logging
import uuid
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session

from app.models.models import Alert, DetectionResult, DetectionIndicator, AnalysisSession
from app.dns.risk_scoring import RiskScorer

logger = logging.getLogger(__name__)


class AlertService:
    SEVERITY_RANGES = {
        "LOW": (0, 24),
        "MEDIUM": (25, 49),
        "HIGH": (50, 74),
        "CRITICAL": (75, 100),
    }

    def __init__(self):
        self.risk_scorer = RiskScorer()

    def calculate_severity(self, risk_score: int) -> str:
        for severity, (min_score, max_score) in self.SEVERITY_RANGES.items():
            if min_score <= risk_score <= max_score:
                return severity
        return "LOW"

    def create_alert_from_detection(
        self, db: Session, detection_result: DetectionResult
    ) -> Optional[Alert]:
        try:
            risk_score = int(detection_result.risk_score) if detection_result.risk_score else 0
            severity = self.calculate_severity(risk_score)

            existing_alert = db.query(Alert).filter(
                Alert.detection_result_id == detection_result.id
            ).first()
            if existing_alert:
                logger.info(f"Alert already exists for detection result {detection_result.id}")
                return existing_alert

            matched_rules = []
            detection_reasons = []
            observed_values = {}
            thresholds = {}
            rule_weights = {}

            for ind in detection_result.indicators:
                if ind.matched:
                    matched_rules.append({
                        "rule_id": ind.rule_id,
                        "indicator": ind.indicator_name,
                        "observed_value": ind.observed_value,
                        "threshold": ind.threshold,
                        "weight": ind.weight,
                        "explanation": ind.explanation,
                    })

                    detection_reasons.append({
                        "rule": ind.rule_id,
                        "reason": ind.explanation,
                    })

                    if ind.rule_id:
                        observed_values[ind.rule_id] = ind.observed_value
                        thresholds[ind.rule_id] = ind.threshold
                        rule_weights[ind.rule_id] = ind.weight

            alert = Alert(
                alert_id=str(uuid.uuid4()),
                detection_result_id=detection_result.id,
                source_ip=detection_result.source_ip,
                destination_ip=None,
                domain=detection_result.base_domain,
                normalized_domain=detection_result.base_domain,
                query_type=None,
                risk_score=risk_score,
                severity=severity,
                matched_rules=matched_rules if matched_rules else None,
                detection_reasons=detection_reasons if detection_reasons else None,
                observed_values=observed_values if observed_values else None,
                thresholds=thresholds if thresholds else None,
                rule_weights=rule_weights if rule_weights else None,
            )

            db.add(alert)
            db.commit()
            db.refresh(alert)

            logger.info(f"Created alert {alert.alert_id} with severity {severity} for detection result {detection_result.id}")
            return alert

        except Exception as e:
            logger.error(f"Error creating alert for detection result {detection_result.id}: {e}")
            db.rollback()
            return None

    def get_alert(self, db: Session, alert_id: int) -> Optional[Alert]:
        return db.query(Alert).filter(Alert.id == alert_id).first()

    def get_alert_by_uuid(self, db: Session, alert_uuid: str) -> Optional[Alert]:
        return db.query(Alert).filter(Alert.alert_id == alert_uuid).first()

    def list_alerts(
        self,
        db: Session,
        skip: int = 0,
        limit: int = 100,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        domain: Optional[str] = None,
        acknowledged: Optional[bool] = None,
    ) -> List[Alert]:
        query = db.query(Alert).order_by(Alert.created_at.desc())

        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)
        if domain:
            query = query.filter(Alert.domain.ilike(f"%{domain}%"))
        if acknowledged is not None:
            query = query.filter(Alert.acknowledged == acknowledged)

        return query.offset(skip).limit(limit).all()

    def count_alerts(
        self,
        db: Session,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        domain: Optional[str] = None,
        acknowledged: Optional[bool] = None,
    ) -> int:
        query = db.query(Alert)

        if severity:
            query = query.filter(Alert.severity == severity.upper())
        if source_ip:
            query = query.filter(Alert.source_ip == source_ip)
        if domain:
            query = query.filter(Alert.domain.ilike(f"%{domain}%"))
        if acknowledged is not None:
            query = query.filter(Alert.acknowledged == acknowledged)

        return query.count()

    def acknowledge_alert(self, db: Session, alert_id: int, acknowledged_by: str) -> Optional[Alert]:
        from datetime import datetime
        alert = self.get_alert(db, alert_id)
        if alert:
            alert.acknowledged = True
            alert.acknowledged_at = datetime.utcnow()
            alert.acknowledged_by = acknowledged_by
            db.commit()
            db.refresh(alert)
            logger.info(f"Alert {alert.alert_id} acknowledged by {acknowledged_by}")
        return alert


def create_alert_for_detection(db: Session, detection_result: DetectionResult) -> Optional[Alert]:
    service = AlertService()
    return service.create_alert_from_detection(db, detection_result)