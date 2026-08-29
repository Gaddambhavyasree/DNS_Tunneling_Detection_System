from typing import List, Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session

from app.models.models import AnalysisSession, DNSQuery, DetectionResult, DetectionIndicator
from app.dns.feature_extractor import (
    group_queries_by_source_and_domain,
    extract_features_for_group,
    ExtractedFeatures,
    ExtractionConfig,
    DEFAULT_CONFIG,
)
from app.dns.rules import RuleEngine, RuleResult
from app.dns.risk_scoring import RiskScorer
from app.dns.alert_service import create_alert_for_detection


class DetectionService:
    def __init__(self, config: ExtractionConfig = DEFAULT_CONFIG):
        self.config = config
        self.rule_engine = RuleEngine(config)
        self.risk_scorer = RiskScorer()
    
    def run_detection(self, db: Session, session_id: int) -> List[DetectionResult]:
        session = db.query(AnalysisSession).filter(AnalysisSession.id == session_id).first()
        if not session:
            raise ValueError(f"Session {session_id} not found")
        
        queries = db.query(DNSQuery).filter(
            DNSQuery.session_id == session_id,
            DNSQuery.is_query == True
        ).order_by(DNSQuery.timestamp).all()
        
        if not queries:
            return []
        
        query_dicts = [
            {
                "source_ip": q.source_ip,
                "query_name": q.query_name,
                "query_type": q.query_type,
                "query_type_name": q.query_type_name,
                "response_code": q.response_code,
                "response_code_name": q.response_code_name,
                "timestamp": q.timestamp,
            }
            for q in queries
        ]
        
        groups = group_queries_by_source_and_domain(query_dicts)
        
        detection_results = []
        
        for group_key, group_queries in groups.items():
            features = extract_features_for_group(group_queries, self.config)
            rule_results = self.rule_engine.evaluate(features)
            
            risk_score = self.risk_scorer.calculate_risk_score(rule_results)
            detection_status = self.risk_scorer.get_detection_status(risk_score)
            matched_rule_ids = self.risk_scorer.get_matched_rule_ids(rule_results)
            matched_count = len(matched_rule_ids)
            
            detection_result = DetectionResult(
                session_id=session_id,
                source_ip=features.source_ip,
                base_domain=features.base_domain,
                detection_status=detection_status,
                total_queries=features.total_queries,
                unique_subdomains=features.unique_subdomains,
                avg_label_length=features.avg_label_length,
                max_label_length=features.max_label_length,
                avg_entropy=features.avg_entropy,
                max_entropy=features.max_entropy,
                encoding_detected=features.encoding_detected,
                encoding_types=features.encoding_types,
                queries_per_minute=features.queries_per_minute,
                txt_query_count=features.txt_query_count,
                null_query_count=features.null_query_count,
                nxdomain_count=features.nxdomain_count,
                nxdomain_ratio=features.nxdomain_ratio,
                burst_detected=features.burst_detected,
                matched_rules_count=matched_count,
                risk_score=float(risk_score),
            )
            
            db.add(detection_result)
            db.flush()
            
            for rule_result in rule_results:
                indicator = DetectionIndicator(
                    detection_result_id=detection_result.id,
                    rule_id=rule_result.rule_id,
                    indicator_name=rule_result.indicator,
                    description=rule_result.explanation,
                    threshold=rule_result.threshold,
                    observed_value=rule_result.value,
                    matched=rule_result.matched,
                    severity=None,
                    weight=float(rule_result.weight),
                    explanation=rule_result.explanation,
                )
                db.add(indicator)
            
            detection_results.append(detection_result)
        
        db.commit()
        
        for dr in detection_results:
            db.refresh(dr)
        
        # Create alerts for each detection result
        for dr in detection_results:
            create_alert_for_detection(db, dr)
            db.refresh(dr)
        
        return detection_results
    
    def get_detection_results(self, db: Session, session_id: int) -> List[DetectionResult]:
        return db.query(DetectionResult).filter(
            DetectionResult.session_id == session_id
        ).order_by(DetectionResult.matched_rules_count.desc()).all()
    
    def get_detection_result_with_indicators(
        self, db: Session, detection_result_id: int
    ) -> Optional[DetectionResult]:
        return db.query(DetectionResult).filter(
            DetectionResult.id == detection_result_id
        ).first()


def run_detection_for_session(db: Session, session_id: int) -> List[DetectionResult]:
    service = DetectionService()
    return service.run_detection(db, session_id)


def get_detection_results_for_session(db: Session, session_id: int) -> List[DetectionResult]:
    service = DetectionService()
    return service.get_detection_results(db, session_id)