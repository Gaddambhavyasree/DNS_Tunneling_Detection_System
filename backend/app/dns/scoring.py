from typing import List
from app.dns.rules import RuleResult


class RiskScorer:
    def __init__(self, max_score: float = 100.0):
        self.max_score = max_score
    
    def calculate_risk_score(self, rule_results: List[RuleResult]) -> float:
        if not rule_results:
            return 0.0
        
        total_weight = sum(r.weight for r in rule_results if r.matched)
        max_possible_weight = sum(r.weight for r in rule_results)
        
        if max_possible_weight == 0:
            return 0.0
        
        score = (total_weight / max_possible_weight) * self.max_score
        return min(score, self.max_score)
    
    def determine_detection_status(self, risk_score: float) -> str:
        if risk_score >= 70.0:
            return "HIGH_RISK"
        elif risk_score >= 30.0:
            return "SUSPICIOUS"
        else:
            return "NORMAL"
    
    def get_matched_rules_count(self, rule_results: List[RuleResult]) -> int:
        return sum(1 for r in rule_results if r.matched)
    
    def get_severity_breakdown(self, rule_results: List[RuleResult]) -> dict:
        breakdown = {"high": 0, "medium": 0, "low": 0}
        for r in rule_results:
            if r.matched:
                breakdown[r.severity] = breakdown.get(r.severity, 0) + 1
        return breakdown