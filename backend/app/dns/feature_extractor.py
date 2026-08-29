import math
import re
from collections import Counter
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class ExtractionConfig:
    SUBDOMAIN_LENGTH_THRESHOLD: int = 50
    ENTROPY_THRESHOLD: float = 4.5
    QUERY_FREQUENCY_THRESHOLD: float = 100.0
    UNIQUE_SUBDOMAIN_THRESHOLD: int = 50
    NXDOMAIN_RATIO_THRESHOLD: float = 0.60
    BURST_WINDOW_SECONDS: int = 10
    BURST_QUERY_THRESHOLD: int = 20


DEFAULT_CONFIG = ExtractionConfig()


@dataclass
class ExtractedFeatures:
    source_ip: str
    base_domain: str
    total_queries: int = 0
    unique_subdomains: int = 0
    avg_label_length: float = 0.0
    max_label_length: int = 0
    avg_entropy: float = 0.0
    max_entropy: float = 0.0
    encoding_detected: bool = False
    encoding_types: List[str] = field(default_factory=list)
    queries_per_minute: float = 0.0
    txt_query_count: int = 0
    null_query_count: int = 0
    nxdomain_count: int = 0
    nxdomain_ratio: float = 0.0
    burst_detected: bool = False
    subdomain_lengths: List[int] = field(default_factory=list)
    entropy_values: List[float] = field(default_factory=list)
    query_timestamps: List[datetime] = field(default_factory=list)
    query_types: Dict[str, int] = field(default_factory=dict)
    response_codes: Dict[int, int] = field(default_factory=dict)


def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    
    counter = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def extract_subdomain_parts(query_name: str) -> Tuple[str, List[str]]:
    if not query_name:
        return "", []
    
    parts = query_name.rstrip(".").split(".")
    if len(parts) < 2:
        return query_name, []
    
    base_domain = ".".join(parts[-2:])
    subdomain_parts = parts[:-2]
    
    return base_domain, subdomain_parts


def detect_encoding(label: str) -> List[str]:
    detected = []
    label_clean = label.lower()
    
    if re.fullmatch(r"[0-9a-f]+", label_clean) and len(label_clean) % 2 == 0 and len(label_clean) >= 8:
        try:
            bytes.fromhex(label_clean)
            detected.append("hex")
        except ValueError:
            pass
    
    if re.fullmatch(r"[a-z2-7]+=*", label_clean):
        padding_count = label_clean.count("=")
        clean_label = label_clean.rstrip("=")
        if len(clean_label) % 8 == 0 and len(clean_label) >= 8:
            detected.append("base32")
    
    if re.fullmatch(r"[a-z0-9+/]+=*", label_clean):
        padding_count = label_clean.count("=")
        clean_label = label_clean.rstrip("=")
        if len(clean_label) % 4 == 0 and len(clean_label) >= 8:
            try:
                import base64
                base64.b64decode(label_clean, validate=True)
                detected.append("base64")
            except Exception:
                pass
    
    return detected


def calculate_burst(query_timestamps: List[datetime], window_seconds: int = 10, threshold: int = 20) -> bool:
    if len(query_timestamps) < threshold:
        return False
    
    sorted_timestamps = sorted(query_timestamps)
    
    for i in range(len(sorted_timestamps)):
        window_start = sorted_timestamps[i]
        window_end = window_start.timestamp() + window_seconds
        count = 1
        
        for j in range(i + 1, len(sorted_timestamps)):
            if sorted_timestamps[j].timestamp() <= window_end:
                count += 1
            else:
                break
        
        if count >= threshold:
            return True
    
    return False


def extract_features_for_group(
    queries: List[Dict[str, Any]],
    config: ExtractionConfig = DEFAULT_CONFIG
) -> ExtractedFeatures:
    if not queries:
        return ExtractedFeatures(source_ip="", base_domain="")
    
    source_ip = queries[0].get("source_ip", "")
    
    all_query_names = [q.get("query_name", "") for q in queries if q.get("query_name")]
    
    if not all_query_names:
        return ExtractedFeatures(source_ip=source_ip, base_domain="")
    
    base_domains = []
    subdomain_labels = []
    entropy_values = []
    subdomain_lengths = []
    all_encoding_types = set()
    query_timestamps = []
    query_types = Counter()
    response_codes = Counter()
    
    for q in queries:
        query_name = q.get("query_name", "")
        if not query_name:
            continue
        
        base_domain, subdomain_parts = extract_subdomain_parts(query_name)
        if base_domain:
            base_domains.append(base_domain)
        
        for part in subdomain_parts:
            if part:
                subdomain_labels.append(part)
                length = len(part)
                subdomain_lengths.append(length)
                entropy = calculate_shannon_entropy(part)
                entropy_values.append(entropy)
                
                encodings = detect_encoding(part)
                all_encoding_types.update(encodings)
        
        timestamp = q.get("timestamp")
        if isinstance(timestamp, datetime):
            query_timestamps.append(timestamp)
        elif isinstance(timestamp, (int, float)):
            query_timestamps.append(datetime.fromtimestamp(timestamp))
        
        qtype = q.get("query_type_name", "UNKNOWN")
        query_types[qtype] += 1
        
        rcode = q.get("response_code")
        if rcode is not None:
            response_codes[rcode] += 1
    
    base_domain = max(set(base_domains), key=base_domains.count) if base_domains else ""
    
    total_queries = len(queries)
    unique_subdomains = len(set(subdomain_labels)) if subdomain_labels else 0
    
    avg_label_length = sum(subdomain_lengths) / len(subdomain_lengths) if subdomain_lengths else 0.0
    max_label_length = max(subdomain_lengths) if subdomain_lengths else 0
    
    avg_entropy = sum(entropy_values) / len(entropy_values) if entropy_values else 0.0
    max_entropy = max(entropy_values) if entropy_values else 0.0
    
    encoding_detected = len(all_encoding_types) > 0
    encoding_types = list(all_encoding_types)
    
    time_span_minutes = 0.0
    if len(query_timestamps) >= 2:
        sorted_ts = sorted(query_timestamps)
        time_span_seconds = (sorted_ts[-1] - sorted_ts[0]).total_seconds()
        time_span_minutes = max(time_span_seconds / 60.0, 1.0 / 60.0)
    
    queries_per_minute = total_queries / time_span_minutes if time_span_minutes > 0 else 0.0
    
    txt_query_count = query_types.get("TXT", 0)
    null_query_count = query_types.get("NULL", 0)
    
    nxdomain_count = response_codes.get(3, 0)
    total_responses = sum(response_codes.values())
    nxdomain_ratio = nxdomain_count / total_responses if total_responses > 0 else 0.0
    
    burst_detected = calculate_burst(
        query_timestamps,
        config.BURST_WINDOW_SECONDS,
        config.BURST_QUERY_THRESHOLD
    )
    
    return ExtractedFeatures(
        source_ip=source_ip,
        base_domain=base_domain,
        total_queries=total_queries,
        unique_subdomains=unique_subdomains,
        avg_label_length=avg_label_length,
        max_label_length=max_label_length,
        avg_entropy=avg_entropy,
        max_entropy=max_entropy,
        encoding_detected=encoding_detected,
        encoding_types=encoding_types,
        queries_per_minute=queries_per_minute,
        txt_query_count=txt_query_count,
        null_query_count=null_query_count,
        nxdomain_count=nxdomain_count,
        nxdomain_ratio=nxdomain_ratio,
        burst_detected=burst_detected,
        subdomain_lengths=subdomain_lengths,
        entropy_values=entropy_values,
        query_timestamps=query_timestamps,
        query_types=dict(query_types),
        response_codes=dict(response_codes),
    )


def group_queries_by_source_and_domain(queries: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    groups = {}
    
    for q in queries:
        source_ip = q.get("source_ip", "unknown")
        query_name = q.get("query_name", "")
        
        if not query_name:
            continue
        
        base_domain, _ = extract_subdomain_parts(query_name)
        if not base_domain:
            base_domain = query_name
        
        key = f"{source_ip}|{base_domain}"
        
        if key not in groups:
            groups[key] = []
        groups[key].append(q)
    
    return groups