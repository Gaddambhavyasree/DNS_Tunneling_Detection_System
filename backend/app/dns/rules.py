from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from app.dns.feature_extractor import ExtractedFeatures, ExtractionConfig, DEFAULT_CONFIG


@dataclass
class RuleResult:
    rule_id: str
    indicator: str
    value: Optional[float]
    threshold: Optional[float]
    weight: int
    matched: bool
    explanation: str


class RuleEngine:
    def __init__(self, config: ExtractionConfig = DEFAULT_CONFIG):
        self.config = config
        self.rules = self._define_rules()
    
    def _define_rules(self) -> List[Dict[str, Any]]:
        return [
            {
                "rule_id": "LONG_SUBDOMAIN",
                "indicator": "Unusually long subdomain",
                "description": "Subdomain label length exceeds threshold, indicating potential encoded data",
                "threshold": self.config.SUBDOMAIN_LENGTH_THRESHOLD,
                "weight": 20,
                "check": self._check_long_subdomain,
            },
            {
                "rule_id": "HIGH_ENTROPY",
                "indicator": "High entropy",
                "description": "Subdomain entropy exceeds threshold, suggesting encoded or encrypted data",
                "threshold": self.config.ENTROPY_THRESHOLD,
                "weight": 20,
                "check": self._check_high_entropy,
            },
            {
                "rule_id": "ENCODING_DETECTED",
                "indicator": "Encoding detected",
                "description": "Base64 or Hex encoding detected in subdomain labels",
                "threshold": None,
                "weight": 15,
                "check": self._check_encoding_detected,
            },
            {
                "rule_id": "HIGH_QUERY_FREQUENCY",
                "indicator": "High query frequency",
                "description": "DNS query rate exceeds threshold, indicating potential automated tunneling",
                "threshold": self.config.QUERY_FREQUENCY_THRESHOLD,
                "weight": 15,
                "check": self._check_high_query_frequency,
            },
            {
                "rule_id": "EXCESSIVE_UNIQUE_SUBDOMAINS",
                "indicator": "Excessive unique subdomains",
                "description": "Number of unique subdomains exceeds threshold, suggesting algorithmic generation",
                "threshold": self.config.UNIQUE_SUBDOMAIN_THRESHOLD,
                "weight": 15,
                "check": self._check_excessive_unique_subdomains,
            },
            {
                "rule_id": "UNUSUAL_DNS_RECORD",
                "indicator": "Unusual DNS record type",
                "description": "High volume of TXT or NULL queries, often used for data exfiltration",
                "threshold": 10.0,
                "weight": 10,
                "check": self._check_unusual_dns_record,
            },
            {
                "rule_id": "HIGH_NXDOMAIN_RATIO",
                "indicator": "High NXDOMAIN ratio",
                "description": "High ratio of NXDOMAIN responses, indicating non-existent domain generation",
                "threshold": self.config.NXDOMAIN_RATIO_THRESHOLD,
                "weight": 5,
                "check": self._check_high_nxdomain_ratio,
            },
        ]
    
    def evaluate(self, features: ExtractedFeatures) -> List[RuleResult]:
        results = []
        for rule in self.rules:
            result = rule["check"](features, rule)
            results.append(result)
        return results
    
    def _check_long_subdomain(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        observed = float(features.max_label_length)
        matched = observed > threshold
        
        if matched:
            explanation = (
                f"Subdomain label length ({int(observed)}) exceeds threshold ({int(threshold)}). "
                f"Long labels may indicate encoded payload data."
            )
        else:
            explanation = (
                f"Subdomain label length ({int(observed)}) is within threshold ({int(threshold)})."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_high_entropy(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        observed = features.max_entropy
        matched = observed > threshold
        
        if matched:
            explanation = (
                f"Entropy ({observed:.2f}) exceeds threshold ({threshold:.2f}). "
                f"High entropy suggests random or encoded data."
            )
        else:
            explanation = (
                f"Entropy ({observed:.2f}) is within threshold ({threshold:.2f})."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_encoding_detected(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        matched = features.encoding_detected
        observed = 1.0 if matched else 0.0
        threshold = 1.0
        
        if matched:
            encodings = ", ".join(features.encoding_types)
            explanation = f"Detected encoding: {encodings}. These encodings are commonly used to obfuscate data in DNS tunneling."
        else:
            explanation = "No Base64 or Hex encoding detected in subdomain labels."
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_high_query_frequency(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        observed = features.queries_per_minute
        matched = observed > threshold
        
        if matched:
            explanation = (
                f"Query rate ({observed:.1f} queries/min) exceeds threshold ({threshold:.1f} queries/min). "
                f"High frequency may indicate automated tunneling."
            )
        else:
            explanation = (
                f"Query rate ({observed:.1f} queries/min) is within threshold ({threshold:.1f} queries/min)."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_excessive_unique_subdomains(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        observed = float(features.unique_subdomains)
        matched = observed > threshold
        
        if matched:
            explanation = (
                f"Unique subdomains ({int(observed)}) exceeds threshold ({int(threshold)}). "
                f"May indicate algorithmic domain generation."
            )
        else:
            explanation = (
                f"Unique subdomains ({int(observed)}) is within threshold ({int(threshold)})."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_unusual_dns_record(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        txt_count = features.txt_query_count
        null_count = features.null_query_count
        total_suspicious = txt_count + null_count
        observed = float(total_suspicious)
        matched = total_suspicious > threshold
        
        if matched:
            explanation = (
                f"TXT ({txt_count}) + NULL ({null_count}) queries = {total_suspicious}, "
                f"exceeds threshold ({int(threshold)}). Used for data exfiltration."
            )
        else:
            explanation = (
                f"TXT ({txt_count}) + NULL ({null_count}) queries = {total_suspicious}, "
                f"within threshold ({int(threshold)})."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )
    
    def _check_high_nxdomain_ratio(self, features: ExtractedFeatures, rule: Dict[str, Any]) -> RuleResult:
        threshold = rule["threshold"]
        observed = features.nxdomain_ratio
        matched = observed > threshold
        
        if matched:
            explanation = (
                f"NXDOMAIN ratio ({observed:.1%}) exceeds threshold ({threshold:.1%}). "
                f"May indicate domain generation algorithms."
            )
        else:
            explanation = (
                f"NXDOMAIN ratio ({observed:.1%}) is within threshold ({threshold:.1%})."
            )
        
        return RuleResult(
            rule_id=rule["rule_id"],
            indicator=rule["indicator"],
            value=observed,
            threshold=threshold,
            weight=rule["weight"],
            matched=matched,
            explanation=explanation,
        )