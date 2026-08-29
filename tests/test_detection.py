import os
import base64
import tempfile
from datetime import datetime, timedelta

import pytest
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

from app.dns.feature_extractor import (
    ExtractedFeatures,
    ExtractionConfig,
    DEFAULT_CONFIG,
    calculate_shannon_entropy,
    extract_subdomain_parts,
    detect_encoding,
    calculate_burst,
    extract_features_for_group,
    group_queries_by_source_and_domain,
)
from app.dns.rules import RuleEngine, RuleResult
from app.dns.detection import DetectionService, run_detection_for_session, get_detection_results_for_session
from app.models.models import DetectionResult, DetectionIndicator, AnalysisSession, DNSQuery
from app.services.database_service import create_session, save_dns_queries, update_session_completed
from app.schemas.schemas import ProcessingStatus


def make_ts(base: datetime, index: int, interval: float = 0.05) -> datetime:
    return base + timedelta(seconds=index * interval)


def make_tunnel_query_dicts(count: int = 60, base_domain: str = "tunnel.example.com") -> list:
    base = datetime(2024, 1, 1, 12, 0, 0)
    queries = []
    for i in range(count):
        label = base64.b32encode(os.urandom(35)).decode().lower()
        is_txt = i < 11
        queries.append(
            {
                "source_ip": "192.168.1.100",
                "query_name": f"{label}.{base_domain}",
                "query_type": 16 if is_txt else 1,
                "query_type_name": "TXT" if is_txt else "A",
                "response_code": 3,
                "response_code_name": "NXDOMAIN",
                "timestamp": make_ts(base, i),
            }
        )
    return queries


def make_normal_query_dicts() -> list:
    base = datetime(2024, 1, 1, 12, 0, 0)
    return [
        {
            "source_ip": "10.0.0.5",
            "query_name": f"www{i}.example.com",
            "query_type": 1,
            "query_type_name": "A",
            "response_code": 0,
            "response_code_name": "NOERROR",
            "timestamp": make_ts(base, i, 5.0),
        }
        for i in range(5)
    ]


def query_dicts_to_dns_records(query_dicts: list, session_id: int = 1) -> list:
    records = []
    for q in query_dicts:
        records.append(
            {
                "timestamp": q["timestamp"],
                "source_ip": q["source_ip"],
                "destination_ip": "8.8.8.8",
                "transaction_id": 1,
                "query_name": q["query_name"],
                "query_type": q["query_type"],
                "query_type_name": q["query_type_name"],
                "response_code": q["response_code"],
                "response_code_name": q["response_code_name"],
                "answer_count": 0,
                "authority_count": 0,
                "additional_count": 0,
                "packet_size": 100,
                "is_query": True,
                "source_file": "test.pcap",
            }
        )
    return records


def make_rule(**kwargs) -> dict:
    base = {
        "rule_id": "LONG_SUBDOMAIN",
        "indicator": "Test Rule",
        "description": "Test rule description",
        "threshold": 0.0,
        "weight": 15,
    }
    base.update(kwargs)
    return base


def make_features(**kwargs) -> ExtractedFeatures:
    defaults = dict(
        source_ip="192.168.1.100",
        base_domain="example.com",
        total_queries=1,
        unique_subdomains=1,
        avg_label_length=10.0,
        max_label_length=10,
        avg_entropy=2.0,
        max_entropy=2.0,
        encoding_detected=False,
        encoding_types=[],
        queries_per_minute=10.0,
        txt_query_count=0,
        null_query_count=0,
        nxdomain_count=0,
        nxdomain_ratio=0.0,
        burst_detected=False,
    )
    defaults.update(kwargs)
    return ExtractedFeatures(**defaults)


class TestShannonEntropy:
    def test_empty_string(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_single_character(self):
        assert calculate_shannon_entropy("a") == 0.0

    def test_repeated_character(self):
        assert calculate_shannon_entropy("aaaaaaa") == 0.0

    def test_two_characters_uniform(self):
        assert calculate_shannon_entropy("ab") == 1.0

    def test_four_characters_uniform(self):
        assert calculate_shannon_entropy("abcd") == 2.0

    def test_random_string_high_entropy(self):
        entropy = calculate_shannon_entropy("x7kQ2zP9mN4rT8vL5wY")
        assert entropy > 4.0

    def test_entropy_bounded_by_log2_of_alphabet(self):
        entropy = calculate_shannon_entropy("0123456789abcdef" * 3)
        assert entropy <= 4.0 + 1e-9


class TestSubdomainParts:
    def test_simple_subdomain(self):
        base, parts = extract_subdomain_parts("sub.example.com")
        assert base == "example.com"
        assert parts == ["sub"]

    def test_deep_subdomain(self):
        base, parts = extract_subdomain_parts("a.b.c.example.com")
        assert base == "example.com"
        assert parts == ["a", "b", "c"]

    def test_no_subdomain(self):
        base, parts = extract_subdomain_parts("example.com")
        assert base == "example.com"
        assert parts == []

    def test_single_label(self):
        base, parts = extract_subdomain_parts("localhost")
        assert base == "localhost"
        assert parts == []

    def test_trailing_dot(self):
        base, parts = extract_subdomain_parts("sub.example.com.")
        assert base == "example.com"
        assert parts == ["sub"]

    def test_empty_name(self):
        base, parts = extract_subdomain_parts("")
        assert base == ""
        assert parts == []

    def test_none_name(self):
        base, parts = extract_subdomain_parts(None)
        assert base == ""
        assert parts == []


class TestEncodingDetection:
    def test_hex_detected(self):
        detected = detect_encoding("deadbeefaa")
        assert "hex" in detected

    def test_hex_not_other_encodings(self):
        detected = detect_encoding("deadbeefaa")
        assert "base32" not in detected
        assert "base64" not in detected

    def test_base32_detected(self):
        label = base64.b32encode(os.urandom(10)).decode().lower()
        detected = detect_encoding(label)
        assert "base32" in detected

    def test_base64_detected(self):
        detected = detect_encoding("YWJjZGVm")
        assert "base64" in detected

    def test_short_label_no_encoding(self):
        assert detect_encoding("www") == []

    def test_common_word_no_encoding(self):
        assert detect_encoding("example") == []

    def test_case_insensitive(self):
        detected = detect_encoding("DEADBEEFAA")
        assert "hex" in detected


class TestBurstDetection:
    def test_burst_detected(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        timestamps = [make_ts(base, i, 0.5) for i in range(25)]
        assert calculate_burst(timestamps, window_seconds=10, threshold=20) is True

    def test_burst_not_detected(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        timestamps = [make_ts(base, i, 1.0) for i in range(25)]
        assert calculate_burst(timestamps, window_seconds=10, threshold=20) is False

    def test_too_few_queries(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        timestamps = [make_ts(base, i, 0.1) for i in range(5)]
        assert calculate_burst(timestamps, window_seconds=10, threshold=20) is False

    def test_empty_timestamps(self):
        assert calculate_burst([], window_seconds=10, threshold=20) is False

    def test_custom_config(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        timestamps = [make_ts(base, i, 0.5) for i in range(10)]
        assert calculate_burst(timestamps, window_seconds=10, threshold=10) is True


class TestFeatureExtraction:
    def test_tunnel_group_features(self):
        queries = make_tunnel_query_dicts()
        features = extract_features_for_group(queries)

        assert features.source_ip == "192.168.1.100"
        assert features.base_domain == "example.com"
        assert features.total_queries == 60
        assert features.unique_subdomains > 50
        assert features.max_label_length > 50
        assert features.max_entropy > 4.5
        assert features.encoding_detected is True
        assert "base32" in features.encoding_types
        assert features.queries_per_minute > 100
        assert features.txt_query_count == 11
        assert features.nxdomain_count == 60
        assert features.nxdomain_ratio > 0.6
        assert features.burst_detected is True

    def test_normal_group_features(self):
        features = extract_features_for_group(make_normal_query_dicts())

        assert features.source_ip == "10.0.0.5"
        assert features.total_queries == 5
        assert features.max_label_length < 50
        assert features.encoding_detected is False
        assert features.nxdomain_ratio == 0.0
        assert features.burst_detected is False
        assert features.unique_subdomains == 5

    def test_empty_group(self):
        features = extract_features_for_group([])
        assert features.source_ip == ""
        assert features.base_domain == ""
        assert features.total_queries == 0

    def test_queries_without_query_name(self):
        queries = [
            {"source_ip": "1.2.3.4", "query_name": "", "timestamp": datetime(2024, 1, 1)},
            {"source_ip": "1.2.3.4", "query_name": None, "timestamp": datetime(2024, 1, 1)},
        ]
        features = extract_features_for_group(queries)
        assert features.base_domain == ""
        assert features.total_queries == 0

    def test_query_type_counts(self):
        queries = [
            {"source_ip": "1.2.3.4", "query_name": "a.example.com", "query_type_name": "TXT",
             "response_code": 0, "timestamp": make_ts(datetime(2024, 1, 1), 0)},
            {"source_ip": "1.2.3.4", "query_name": "b.example.com", "query_type_name": "A",
             "response_code": 3, "timestamp": make_ts(datetime(2024, 1, 1), 1)},
        ]
        features = extract_features_for_group(queries)
        assert features.txt_query_count == 1
        assert features.nxdomain_count == 1
        assert features.nxdomain_ratio == 0.5

    def test_timestamp_int_support(self):
        queries = [
            {"source_ip": "1.2.3.4", "query_name": "a.example.com", "query_type_name": "A",
             "response_code": 0, "timestamp": 1704110400},
            {"source_ip": "1.2.3.4", "query_name": "b.example.com", "query_type_name": "A",
             "response_code": 0, "timestamp": 1704110401},
        ]
        features = extract_features_for_group(queries)
        assert len(features.query_timestamps) == 2
        assert features.queries_per_minute > 0


class TestGrouping:
    def test_groups_by_source_and_domain(self):
        queries = [
            {"source_ip": "1.1.1.1", "query_name": "a.example.com", "timestamp": datetime(2024, 1, 1)},
            {"source_ip": "1.1.1.1", "query_name": "b.example.com", "timestamp": datetime(2024, 1, 1)},
            {"source_ip": "2.2.2.2", "query_name": "c.example.com", "timestamp": datetime(2024, 1, 1)},
            {"source_ip": "2.2.2.2", "query_name": "d.other.org", "timestamp": datetime(2024, 1, 1)},
        ]
        groups = group_queries_by_source_and_domain(queries)
        assert len(groups) == 3
        assert groups["1.1.1.1|example.com"]
        assert groups["2.2.2.2|example.com"]
        assert groups["2.2.2.2|other.org"]

    def test_skips_empty_query_names(self):
        queries = [
            {"source_ip": "1.1.1.1", "query_name": "", "timestamp": datetime(2024, 1, 1)},
            {"source_ip": "1.1.1.1", "query_name": None, "timestamp": datetime(2024, 1, 1)},
        ]
        groups = group_queries_by_source_and_domain(queries)
        assert groups == {}

    def test_single_label_falls_back_to_query_name(self):
        queries = [{"source_ip": "1.1.1.1", "query_name": "localhost", "timestamp": datetime(2024, 1, 1)}]
        groups = group_queries_by_source_and_domain(queries)
        assert "1.1.1.1|localhost" in groups


class TestRuleEngine:
    def test_evaluate_returns_all_rules(self):
        engine = RuleEngine()
        results = engine.evaluate(make_features())
        assert len(results) == 7
        rule_ids = {r.rule_id for r in results}
        expected_ids = {
            "LONG_SUBDOMAIN",
            "HIGH_ENTROPY",
            "ENCODING_DETECTED",
            "HIGH_QUERY_FREQUENCY",
            "EXCESSIVE_UNIQUE_SUBDOMAINS",
            "UNUSUAL_DNS_RECORD",
            "HIGH_NXDOMAIN_RATIO",
        }
        assert rule_ids == expected_ids

    def test_rule_long_subdomain_matched(self):
        engine = RuleEngine()
        result = engine._check_long_subdomain(
            make_features(max_label_length=55),
            make_rule(rule_id="LONG_SUBDOMAIN", threshold=50, weight=20),
        )
        assert result.matched is True
        assert result.value == 55.0
        assert result.rule_id == "LONG_SUBDOMAIN"
        assert result.weight == 20

    def test_rule_long_subdomain_not_matched(self):
        engine = RuleEngine()
        result = engine._check_long_subdomain(
            make_features(max_label_length=10),
            make_rule(rule_id="LONG_SUBDOMAIN", threshold=50, weight=20),
        )
        assert result.matched is False
        assert result.value == 10.0

    def test_rule_long_subdomain_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_long_subdomain(
            make_features(max_label_length=50),
            make_rule(rule_id="LONG_SUBDOMAIN", threshold=50, weight=20),
        )
        assert result.matched is False  # Strictly greater than

    def test_rule_high_entropy_matched(self):
        engine = RuleEngine()
        result = engine._check_high_entropy(
            make_features(max_entropy=5.5),
            make_rule(rule_id="HIGH_ENTROPY", threshold=4.5, weight=20),
        )
        assert result.matched is True
        assert result.value == 5.5
        assert result.rule_id == "HIGH_ENTROPY"
        assert result.weight == 20

    def test_rule_high_entropy_not_matched(self):
        engine = RuleEngine()
        result = engine._check_high_entropy(
            make_features(max_entropy=2.0),
            make_rule(rule_id="HIGH_ENTROPY", threshold=4.5, weight=20),
        )
        assert result.matched is False

    def test_rule_high_entropy_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_high_entropy(
            make_features(max_entropy=4.5),
            make_rule(rule_id="HIGH_ENTROPY", threshold=4.5, weight=20),
        )
        assert result.matched is False  # Strictly greater than

    def test_rule_encoding_detected_matched(self):
        engine = RuleEngine()
        result = engine._check_encoding_detected(
            make_features(encoding_detected=True, encoding_types=["base64"]),
            make_rule(rule_id="ENCODING_DETECTED", threshold=1.0, weight=15),
        )
        assert result.matched is True
        assert "base64" in result.explanation
        assert result.rule_id == "ENCODING_DETECTED"
        assert result.weight == 15

    def test_rule_encoding_detected_not_matched(self):
        engine = RuleEngine()
        result = engine._check_encoding_detected(
            make_features(),
            make_rule(rule_id="ENCODING_DETECTED", threshold=1.0, weight=15),
        )
        assert result.matched is False

    def test_rule_high_query_frequency_matched(self):
        engine = RuleEngine()
        result = engine._check_high_query_frequency(
            make_features(queries_per_minute=500.0),
            make_rule(rule_id="HIGH_QUERY_FREQUENCY", threshold=100.0, weight=15),
        )
        assert result.matched is True
        assert result.value == 500.0
        assert result.rule_id == "HIGH_QUERY_FREQUENCY"
        assert result.weight == 15

    def test_rule_high_query_frequency_not_matched(self):
        engine = RuleEngine()
        result = engine._check_high_query_frequency(
            make_features(queries_per_minute=10.0),
            make_rule(rule_id="HIGH_QUERY_FREQUENCY", threshold=100.0, weight=15),
        )
        assert result.matched is False

    def test_rule_high_query_frequency_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_high_query_frequency(
            make_features(queries_per_minute=100.0),
            make_rule(rule_id="HIGH_QUERY_FREQUENCY", threshold=100.0, weight=15),
        )
        assert result.matched is False  # Strictly greater than

    def test_rule_excessive_unique_subdomains_matched(self):
        engine = RuleEngine()
        result = engine._check_excessive_unique_subdomains(
            make_features(unique_subdomains=60),
            make_rule(rule_id="EXCESSIVE_UNIQUE_SUBDOMAINS", threshold=50, weight=15),
        )
        assert result.matched is True
        assert result.value == 60.0
        assert result.rule_id == "EXCESSIVE_UNIQUE_SUBDOMAINS"
        assert result.weight == 15

    def test_rule_excessive_unique_subdomains_not_matched(self):
        engine = RuleEngine()
        result = engine._check_excessive_unique_subdomains(
            make_features(unique_subdomains=5),
            make_rule(rule_id="EXCESSIVE_UNIQUE_SUBDOMAINS", threshold=50, weight=15),
        )
        assert result.matched is False

    def test_rule_excessive_unique_subdomains_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_excessive_unique_subdomains(
            make_features(unique_subdomains=50),
            make_rule(rule_id="EXCESSIVE_UNIQUE_SUBDOMAINS", threshold=50, weight=15),
        )
        assert result.matched is False  # Strictly greater than

    def test_rule_unusual_dns_record_matched(self):
        engine = RuleEngine()
        result = engine._check_unusual_dns_record(
            make_features(txt_query_count=8, null_query_count=5),
            make_rule(rule_id="UNUSUAL_DNS_RECORD", threshold=10.0, weight=10),
        )
        assert result.matched is True
        assert result.value == 13.0
        assert result.rule_id == "UNUSUAL_DNS_RECORD"
        assert result.weight == 10

    def test_rule_unusual_dns_record_not_matched(self):
        engine = RuleEngine()
        result = engine._check_unusual_dns_record(
            make_features(txt_query_count=2, null_query_count=0),
            make_rule(rule_id="UNUSUAL_DNS_RECORD", threshold=10.0, weight=10),
        )
        assert result.matched is False

    def test_rule_unusual_dns_record_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_unusual_dns_record(
            make_features(txt_query_count=10, null_query_count=0),
            make_rule(rule_id="UNUSUAL_DNS_RECORD", threshold=10.0, weight=10),
        )
        assert result.matched is False  # Strictly greater than

    def test_rule_high_nxdomain_ratio_matched(self):
        engine = RuleEngine()
        result = engine._check_high_nxdomain_ratio(
            make_features(nxdomain_ratio=0.8),
            make_rule(rule_id="HIGH_NXDOMAIN_RATIO", threshold=0.6, weight=5),
        )
        assert result.matched is True
        assert result.value == 0.8
        assert result.rule_id == "HIGH_NXDOMAIN_RATIO"
        assert result.weight == 5

    def test_rule_high_nxdomain_ratio_not_matched(self):
        engine = RuleEngine()
        result = engine._check_high_nxdomain_ratio(
            make_features(nxdomain_ratio=0.1),
            make_rule(rule_id="HIGH_NXDOMAIN_RATIO", threshold=0.6, weight=5),
        )
        assert result.matched is False

    def test_rule_high_nxdomain_ratio_at_threshold(self):
        engine = RuleEngine()
        result = engine._check_high_nxdomain_ratio(
            make_features(nxdomain_ratio=0.6),
            make_rule(rule_id="HIGH_NXDOMAIN_RATIO", threshold=0.6, weight=5),
        )
        assert result.matched is False  # Strictly greater than

    def test_all_normal_features_no_matches(self):
        engine = RuleEngine()
        results = engine.evaluate(make_features())
        assert all(not r.matched for r in results)

    def test_all_rules_match_on_tunnel_features(self):
        engine = RuleEngine()
        features = extract_features_for_group(make_tunnel_query_dicts())
        results = engine.evaluate(features)
        # With tunnel features, all 7 rules should match
        assert all(r.matched for r in results)


class TestDetectionService:
    def test_run_detection_high_risk(self, db):
        session = create_session(db, "tunnel.pcap", "tunnel.pcap")
        records = query_dicts_to_dns_records(make_tunnel_query_dicts())
        save_dns_queries(db, session.id, records)

        results = DetectionService().run_detection(db, session.id)

        assert len(results) == 1
        result = results[0]
        assert result.base_domain == "example.com"
        assert result.source_ip == "192.168.1.100"
        assert result.detection_status == "HIGH_RISK"
        assert result.risk_score is not None
        assert result.risk_score >= 70
        assert result.matched_rules_count >= 6  # Most rules should match
        assert result.total_queries == 60

        indicators = db.query(DetectionIndicator).filter(
            DetectionIndicator.detection_result_id == result.id
        ).all()
        assert len(indicators) == 7  # 7 rules in Module 4

    def test_run_detection_normal(self, db):
        session = create_session(db, "normal.pcap", "normal.pcap")
        records = query_dicts_to_dns_records(make_normal_query_dicts())
        save_dns_queries(db, session.id, records)

        results = DetectionService().run_detection(db, session.id)

        assert len(results) == 1
        result = results[0]
        assert result.detection_status == "NORMAL"
        assert result.risk_score == 0
        assert result.matched_rules_count == 0

    def test_run_detection_no_queries(self, db):
        session = create_session(db, "empty.pcap", "empty.pcap")
        results = DetectionService().run_detection(db, session.id)
        assert results == []

    def test_run_detection_nonexistent_session(self, db):
        with pytest.raises(ValueError):
            DetectionService().run_detection(db, 99999)

    def test_get_detection_results_sorted_by_matched_rules(self, db):
        session = create_session(db, "tunnel.pcap", "tunnel.pcap")
        save_dns_queries(db, session.id, query_dicts_to_dns_records(make_tunnel_query_dicts()))
        DetectionService().run_detection(db, session.id)

        results = DetectionService().get_detection_results(db, session.id)
        assert len(results) == 1
        assert results[0].matched_rules_count == 7

    def test_detection_results_persisted(self, db):
        session = create_session(db, "tunnel.pcap", "tunnel.pcap")
        save_dns_queries(db, session.id, query_dicts_to_dns_records(make_tunnel_query_dicts()))
        DetectionService().run_detection(db, session.id)

        stored = db.query(DetectionResult).filter(DetectionResult.session_id == session.id).all()
        assert len(stored) == 1
        assert stored[0].detection_status == "HIGH_RISK"
        assert stored[0].risk_score is not None
        assert stored[0].risk_score >= 70


def create_tunnel_pcap_bytes():
    packets = []
    t = 1704110400.0
    for i in range(60):
        label = base64.b32encode(os.urandom(35)).decode().lower()
        qname = f"{label}.tunnel.example.com."
        qtype = 16 if i < 11 else 1
        pkt = (
            Ether()
            / IP(src="192.168.1.100", dst="8.8.8.8")
            / UDP(sport=50000 + i, dport=53)
            / DNS(id=i, qr=0, qd=DNSQR(qname=qname.encode(), qtype=qtype))
        )
        pkt.time = t + i * 0.05
        packets.append(pkt)

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        temp_path = f.name

    try:
        wrpcap(temp_path, packets)
        with open(temp_path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


class TestDetectionAPI:
    def _upload_tunnel_pcap(self, client):
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("tunnel.pcap", create_tunnel_pcap_bytes(), "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 200
        return response.json()

    def test_run_detection_endpoint(self, client):
        upload = self._upload_tunnel_pcap(client)
        session_uuid = upload["session_id"]

        response = client.post(f"/api/analysis/{session_uuid}/detect")

        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["results_count"] >= 1
        assert len(data["results"]) == data["results_count"]

        result = data["results"][0]
        assert result["base_domain"] == "example.com"
        assert result["detection_status"] == "HIGH_RISK"
        assert result["risk_score"] is not None
        assert result["risk_score"] >= 70
        assert result["matched_rules_count"] >= 6  # Most rules should match for tunnel
        assert len(result["indicators"]) == 7  # 7 rules in Module 4

        matched = [ind for ind in result["indicators"] if ind["matched"]]
        assert any(ind["rule_id"] == "ENCODING_DETECTED" for ind in matched)

    def test_get_detection_results_endpoint(self, client):
        upload = self._upload_tunnel_pcap(client)
        session_uuid = upload["session_id"]

        run_response = client.post(f"/api/analysis/{session_uuid}/detect")
        assert run_response.status_code == 200

        response = client.get(f"/api/analysis/{session_uuid}/detection")

        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 1
        result = data["results"][0]
        assert result["id"] == run_response.json()["results"][0]["id"]
        assert result["matched_rules_count"] == run_response.json()["results"][0]["matched_rules_count"]

    def test_detect_no_queries_session(self, client):
        packets = [
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=80) / DNS(),
        ]
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
            temp_path = f.name
        try:
            wrpcap(temp_path, packets)
            with open(temp_path, "rb") as f:
                pcap_data = f.read()
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

        upload_resp = client.post(
            "/api/pcap/upload",
            files={"file": ("nodns.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
        )
        assert upload_resp.status_code == 200
        session_uuid = upload_resp.json()["session_id"]

        response = client.post(f"/api/analysis/{session_uuid}/detect")
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["results_count"] == 0
        assert data["results"] == []

    def test_detect_nonexistent_session(self, client):
        response = client.post("/api/analysis/nonexistent-uuid/detect")
        assert response.status_code == 404

    def test_get_detection_nonexistent_session(self, client):
        response = client.get("/api/analysis/nonexistent-uuid/detection")
        assert response.status_code == 404

    def test_detect_session_not_completed(self, client, db):
        session = create_session(db, "pending.pcap", "pending.pcap")
        session_uuid = session.session_id

        response = client.post(f"/api/analysis/{session_uuid}/detect")
        assert response.status_code == 400
        assert "not ready" in response.json()["detail"].lower()

    def test_detect_completed_session_without_queries(self, client, db):
        session = create_session(db, "complete.pcap", "complete.pcap")
        update_session_completed(
            db,
            session.id,
            total_packets=1,
            dns_packets=1,
            queries_extracted=0,
            processing_duration_ms=10,
            status=ProcessingStatus.COMPLETED,
        )

        response = client.post(f"/api/analysis/{session.session_id}/detect")
        assert response.status_code == 200
        data = response.json()
        assert data["results_count"] == 0
        assert "No DNS queries" in data["message"]

    def test_detection_indicator_fields(self, client):
        upload = self._upload_tunnel_pcap(client)
        response = client.post(f"/api/analysis/{upload['session_id']}/detect")
        data = response.json()

        indicators = data["results"][0]["indicators"]
        for indicator in indicators:
            assert "rule_id" in indicator
            assert "indicator_name" in indicator  # Schema uses indicator_name
            assert "threshold" in indicator
            assert "observed_value" in indicator or "value" in indicator  # Accept both
            assert "matched" in indicator
            assert "weight" in indicator
            assert "explanation" in indicator
            # severity should not be in Module 4 output
            assert "severity" not in indicator or indicator["severity"] is None