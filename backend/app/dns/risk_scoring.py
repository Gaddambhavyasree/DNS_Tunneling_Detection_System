from typing import List
from app.dns.rules import RuleResult


class RiskScorer:
    def __init__(self):
        pass

    def calculate_risk_score(self, rule_results: List[RuleResult]) -> int:
        if not rule_results:
            return 0

        total_score = sum(r.weight for r in rule_results if r.matched)

        if total_score < 0:
            return 0
        if total_score > 100:
            return 100

        return total_score

    def get_matched_rule_ids(self, rule_results: List[RuleResult]) -> List[str]:
        if not rule_results:
            return []
        return [r.rule_id for r in rule_results if r.matched]

    def get_detection_status(self, risk_score: int) -> str:
        if risk_score >= 70:
            return "HIGH_RISK"
        elif risk_score >= 30:
            return "SUSPICIOUS"
        else:
            return "NORMAL"