import base64
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.dns.feature_extractor import calculate_shannon_entropy, extract_subdomain_parts
from app.models.models import DNSQuery

_MIN_LABEL_LENGTH_FOR_ENCODING = 8
_MIN_URL_LABEL_LENGTH = 4

_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")
_URL_ENCODED_PATTERN = re.compile(r"^(?:%[0-9a-fA-F]{2})+$")


@dataclass
class ParsedDomain:
    query_name: str
    normalized_name: str
    base_domain: str
    subdomain: str
    tld: str
    label_count: int
    query_name_length: int
    longest_label_length: int
    subdomain_length: int


@dataclass
class DNSQueryFeature:
    source_ip: Optional[str]
    destination_ip: Optional[str]
    timestamp: Optional[datetime]
    query_name: str
    normalized_name: str
    query_type: Optional[int]
    query_type_name: Optional[str]
    response_code: Optional[int]
    response_code_name: Optional[str]
    is_query: bool
    is_null_query: bool
    is_nxdomain: bool
    is_txt_query: bool
    base_domain: str
    subdomain: str
    tld: str
    label_count: int
    query_name_length: int
    longest_label_length: int
    subdomain_length: int
    entropy: float
    encoding_types: List[str] = field(default_factory=list)


@dataclass
class DNSGroupFeature:
    source_ip: str
    base_domain: str
    query_count: int
    unique_subdomain_count: int
    queries_per_minute: float
    peak_queries_per_minute: float
    rate_ratio: float
    txt_query_count: int
    null_query_count: int
    nxdomain_count: int
    nxdomain_ratio: float
    query_types: Dict[str, int] = field(default_factory=dict)
    response_codes: Dict[int, int] = field(default_factory=dict)
    query_timestamps: List[datetime] = field(default_factory=list)
    queries: List[DNSQueryFeature] = field(default_factory=list)


def normalize_query_name(query_name: Optional[str]) -> str:
    if not query_name:
        return ""
    return query_name.strip().rstrip(".").lower()


def parse_domain(query_name: Optional[str]) -> ParsedDomain:
    normalized = normalize_query_name(query_name)
    labels = [label for label in normalized.split(".") if label]

    base_domain = ".".join(labels[-2:]) if len(labels) >= 2 else (labels[-1] if labels else "")
    subdomain_parts = labels[:-2]
    subdomain = ".".join(subdomain_parts)
    tld = labels[-1] if labels else ""

    return ParsedDomain(
        query_name=query_name or "",
        normalized_name=normalized,
        base_domain=base_domain,
        subdomain=subdomain,
        tld=tld,
        label_count=len(labels),
        query_name_length=len(normalized),
        longest_label_length=max((len(label) for label in labels), default=0),
        subdomain_length=len(subdomain),
    )


def detect_encoding(label: Optional[str]) -> List[str]:
    detected = []
    if not label:
        return detected

    if len(label) >= _MIN_LABEL_LENGTH_FOR_ENCODING:
        if _HEX_PATTERN.fullmatch(label) and len(label) % 2 == 0:
            try:
                bytes.fromhex(label)
                detected.append("hex")
            except ValueError:
                pass

        if _BASE64_PATTERN.fullmatch(label):
            unpadded = label.rstrip("=")
            if len(unpadded) >= _MIN_LABEL_LENGTH_FOR_ENCODING:
                try:
                    base64.b64decode(label, validate=True)
                    detected.append("base64")
                except Exception:
                    pass

    if len(label) >= _MIN_URL_LABEL_LENGTH and _URL_ENCODED_PATTERN.fullmatch(label):
        detected.append("url")

    return detected


def _resolve_timestamp(raw: Any) -> Optional[datetime]:
    if isinstance(raw, datetime):
        return raw
    if isinstance(raw, (int, float)):
        try:
            return datetime.fromtimestamp(raw)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def extract_query_features(record: Dict[str, Any]) -> Optional[DNSQueryFeature]:
    query_name = record.get("query_name")
    if not query_name:
        return None

    parsed = parse_domain(query_name)
    normalized = parsed.normalized_name

    query_type = record.get("query_type")
    query_type_name = record.get("query_type_name")
    response_code = record.get("response_code")
    is_query = bool(record.get("is_query", True))

    is_null_query = normalized == "null" or query_type == 10
    is_nxdomain = (not is_query) and response_code == 3
    is_txt_query = (query_type_name or "").upper() == "TXT" or query_type == 16

    payload_label = ""
    if parsed.subdomain:
        payload_label = max(parsed.subdomain.split("."), key=len)
    if not payload_label:
        payload_label = normalized

    entropy = calculate_shannon_entropy(payload_label)
    encoding_types = detect_encoding(payload_label)

    return DNSQueryFeature(
        source_ip=record.get("source_ip"),
        destination_ip=record.get("destination_ip"),
        timestamp=_resolve_timestamp(record.get("timestamp")),
        query_name=query_name,
        normalized_name=normalized,
        query_type=query_type,
        query_type_name=query_type_name,
        response_code=response_code,
        response_code_name=record.get("response_code_name"),
        is_query=is_query,
        is_null_query=is_null_query,
        is_nxdomain=is_nxdomain,
        is_txt_query=is_txt_query,
        base_domain=parsed.base_domain,
        subdomain=parsed.subdomain,
        tld=parsed.tld,
        label_count=parsed.label_count,
        query_name_length=parsed.query_name_length,
        longest_label_length=parsed.longest_label_length,
        subdomain_length=parsed.subdomain_length,
        entropy=entropy,
        encoding_types=encoding_types,
    )


def _max_queries_in_window(timestamps: List[datetime], window_seconds: int) -> int:
    if not timestamps or window_seconds <= 0:
        return 0
    max_count = 0
    for i in range(len(timestamps)):
        window_end = timestamps[i].timestamp() + window_seconds
        count = 1
        for j in range(i + 1, len(timestamps)):
            if timestamps[j].timestamp() <= window_end:
                count += 1
            else:
                break
        if count > max_count:
            max_count = count
    return max_count


def compute_frequency(
    timestamps: List[datetime],
    window_seconds: int = 60,
    burst_window_seconds: int = 10,
) -> Tuple[float, float, float]:
    valid = sorted(ts for ts in timestamps if ts is not None)
    if not valid:
        return 0.0, 0.0, 0.0

    span_seconds = (valid[-1] - valid[0]).total_seconds()

    if span_seconds <= 0:
        baseline_qpm = len(valid) / (window_seconds / 60.0) if window_seconds > 0 else 0.0
        peak_qpm = len(valid) / (burst_window_seconds / 60.0) if burst_window_seconds > 0 else 0.0
    else:
        baseline_qpm = len(valid) / (span_seconds / 60.0)
        peak_count = _max_queries_in_window(valid, burst_window_seconds)
        peak_qpm = peak_count / (burst_window_seconds / 60.0) if burst_window_seconds > 0 else 0.0

    rate_ratio = peak_qpm / baseline_qpm if baseline_qpm > 0 else 0.0
    return baseline_qpm, peak_qpm, rate_ratio


def group_by_source_and_domain(
    features: List[DNSQueryFeature],
) -> Dict[str, List[DNSQueryFeature]]:
    groups: Dict[str, List[DNSQueryFeature]] = {}
    for feature in features:
        source_ip = feature.source_ip or "unknown"
        base_domain = feature.base_domain or feature.normalized_name
        key = f"{source_ip}|{base_domain}"
        groups.setdefault(key, []).append(feature)
    return groups


def extract_group_features(
    features: List[DNSQueryFeature],
    window_seconds: int = 60,
    burst_window_seconds: int = 10,
) -> DNSGroupFeature:
    if not features:
        return DNSGroupFeature(
            source_ip="",
            base_domain="",
            query_count=0,
            unique_subdomain_count=0,
            queries_per_minute=0.0,
            peak_queries_per_minute=0.0,
            rate_ratio=0.0,
            txt_query_count=0,
            null_query_count=0,
            nxdomain_count=0,
            nxdomain_ratio=0.0,
        )

    source_ip = features[0].source_ip or "unknown"
    base_domain = features[0].base_domain or features[0].normalized_name

    subdomains = {f.subdomain for f in features if f.subdomain}
    timestamps = [f.timestamp for f in features if f.timestamp is not None]
    baseline_qpm, peak_qpm, rate_ratio = compute_frequency(
        timestamps, window_seconds, burst_window_seconds
    )

    query_types = Counter(f.query_type_name or "UNKNOWN" for f in features)
    response_codes = Counter(
        f.response_code for f in features if f.response_code is not None
    )

    txt_query_count = sum(1 for f in features if f.is_txt_query)
    null_query_count = sum(1 for f in features if f.is_null_query)

    response_records = [f for f in features if not f.is_query]
    nxdomain_count = sum(1 for f in response_records if f.response_code == 3)
    nxdomain_ratio = nxdomain_count / len(response_records) if response_records else 0.0

    return DNSGroupFeature(
        source_ip=source_ip,
        base_domain=base_domain,
        query_count=len(features),
        unique_subdomain_count=len(subdomains),
        queries_per_minute=baseline_qpm,
        peak_queries_per_minute=peak_qpm,
        rate_ratio=rate_ratio,
        txt_query_count=txt_query_count,
        null_query_count=null_query_count,
        nxdomain_count=nxdomain_count,
        nxdomain_ratio=nxdomain_ratio,
        query_types=dict(query_types),
        response_codes=dict(response_codes),
        query_timestamps=timestamps,
        queries=features,
    )


def extract_features(
    records: List[Dict[str, Any]],
    window_seconds: int = 60,
    burst_window_seconds: int = 10,
) -> List[DNSGroupFeature]:
    parsed = []
    for record in records:
        try:
            feature = extract_query_features(record)
        except Exception:
            feature = None
        if feature:
            parsed.append(feature)

    groups = group_by_source_and_domain(parsed)
    return [
        extract_group_features(group, window_seconds, burst_window_seconds)
        for group in groups.values()
    ]


def _record_to_dict(row: DNSQuery) -> Dict[str, Any]:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def extract_features_for_session(
    db,
    session_id: int,
    window_seconds: int = 60,
    burst_window_seconds: int = 10,
) -> List[DNSGroupFeature]:
    rows = (
        db.query(DNSQuery)
        .filter(DNSQuery.session_id == session_id)
        .order_by(DNSQuery.timestamp)
        .all()
    )
    records = [_record_to_dict(row) for row in rows]
    return extract_features(records, window_seconds, burst_window_seconds)