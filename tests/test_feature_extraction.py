import base64
import os
import tempfile
from datetime import datetime, timedelta

import pytest
from scapy.all import Ether, IP, UDP, DNS, DNSQR, wrpcap

from app.dns.features import (
    ParsedDomain,
    DNSQueryFeature,
    DNSGroupFeature,
    normalize_query_name,
    parse_domain,
    detect_encoding,
    extract_query_features,
    compute_frequency,
    group_by_source_and_domain,
    extract_group_features,
    extract_features,
    extract_features_for_session,
)
from app.dns.feature_extractor import calculate_shannon_entropy
from app.models.models import AnalysisSession, DNSQuery
from app.services.database_service import (
    create_session,
    save_dns_queries,
    update_session_completed,
)
from app.schemas.schemas import ProcessingStatus


def make_ts(base: datetime, index: int, interval: float = 0.05) -> datetime:
    return base + timedelta(seconds=index * interval)


def make_record(
    query_name: str,
    *,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "8.8.8.8",
    timestamp: datetime = None,
    query_type: int = 1,
    query_type_name: str = "A",
    response_code: int = 0,
    response_code_name: str = "NOERROR",
    is_query: bool = True,
) -> dict:
    return {
        "timestamp": timestamp or datetime(2024, 1, 1, 12, 0, 0),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "transaction_id": 1,
        "query_name": query_name,
        "query_type": query_type,
        "query_type_name": query_type_name,
        "response_code": response_code,
        "response_code_name": response_code_name,
        "answer_count": 0,
        "authority_count": 0,
        "additional_count": 0,
        "packet_size": 100,
        "is_query": is_query,
        "source_file": "test.pcap",
    }


def make_dns_records(query_dicts: list, session_id: int = 1) -> list:
    records = []
    for q in query_dicts:
        records.append(
            {
                "session_id": session_id,
                "timestamp": q["timestamp"],
                "source_ip": q["source_ip"],
                "destination_ip": q.get("destination_ip", "8.8.8.8"),
                "transaction_id": q.get("transaction_id", 1),
                "query_name": q["query_name"],
                "query_type": q["query_type"],
                "query_type_name": q["query_type_name"],
                "response_code": q["response_code"],
                "response_code_name": q["response_code_name"],
                "answer_count": q.get("answer_count", 0),
                "authority_count": q.get("authority_count", 0),
                "additional_count": q.get("additional_count", 0),
                "packet_size": q.get("packet_size", 100),
                "is_query": q.get("is_query", True),
                "source_file": "test.pcap",
            }
        )
    return records


class TestNormalizeAndParseDomain:
    def test_normalize_lowercases_and_strips_trailing_dot(self):
        assert normalize_query_name("WWW.Example.COM.") == "www.example.com"

    def test_normalize_empty(self):
        assert normalize_query_name("") == ""
        assert normalize_query_name(None) == ""

    def test_parse_normal_domain(self):
        parsed = parse_domain("www.example.com")
        assert parsed.base_domain == "example.com"
        assert parsed.subdomain == "www"
        assert parsed.tld == "com"
        assert parsed.label_count == 3
        assert parsed.query_name_length == len("www.example.com")
        assert parsed.longest_label_length == 7
        assert parsed.subdomain_length == 3

    def test_parse_single_label(self):
        parsed = parse_domain("localhost")
        assert parsed.base_domain == "localhost"
        assert parsed.subdomain == ""
        assert parsed.tld == "localhost"
        assert parsed.label_count == 1

    def test_parse_long_subdomain(self):
        label = "a" * 60
        parsed = parse_domain(f"{label}.example.com")
        assert parsed.longest_label_length == 60
        assert parsed.subdomain == label
        assert parsed.subdomain_length == 60

    def test_parse_trailing_dot_and_case(self):
        parsed = parse_domain("SUB.Example.COM.")
        assert parsed.normalized_name == "sub.example.com"
        assert parsed.base_domain == "example.com"

    def test_parse_empty(self):
        parsed = parse_domain(None)
        assert parsed.normalized_name == ""
        assert parsed.label_count == 0
        assert parsed.longest_label_length == 0


class TestEntropy:
    def test_entropy_repeated_characters_zero(self):
        assert calculate_shannon_entropy("aaaa") == 0.0

    def test_entropy_empty_zero(self):
        assert calculate_shannon_entropy("") == 0.0

    def test_entropy_uniform_high(self):
        assert calculate_shannon_entropy("abcdefghijklmnop") == 4.0

    def test_extracted_entropy_uses_longest_label(self):
        record = make_record(f"abcdefghijklmnop.{'z' * 10}.example.com")
        feature = extract_query_features(record)
        assert feature.entropy == pytest.approx(4.0)

    def test_extracted_entropy_no_subdomain_uses_name(self):
        record = make_record("abcdefgh")
        feature = extract_query_features(record)
        assert feature.entropy == pytest.approx(3.0)


class TestEncodingDetection:
    def test_base64_detected(self):
        label = base64.b64encode(b"exfiltration-payload-data" * 2).decode()
        detected = detect_encoding(label)
        assert "base64" in detected

    def test_hex_detected(self):
        detected = detect_encoding("deadbeefcafebabe12345678")
        assert "hex" in detected

    def test_url_encoding_detected(self):
        detected = detect_encoding("%48%45%4c%4c%4f")
        assert "url" in detected

    def test_short_hex_not_detected(self):
        assert detect_encoding("abcde") == []

    def test_random_word_no_encoding(self):
        assert detect_encoding("hello") == []
        assert detect_encoding("") == []
        assert detect_encoding(None) == []

    def test_query_feature_includes_encoding_types(self):
        label = base64.b64encode(b"exfiltration-payload-data" * 2).decode()
        record = make_record(f"{label}.example.com")
        feature = extract_query_features(record)
        assert "base64" in feature.encoding_types


class TestQueryFeatureExtraction:
    def test_normal_query(self):
        record = make_record("www.example.com", source_ip="10.0.0.5")
        feature = extract_query_features(record)
        assert isinstance(feature, DNSQueryFeature)
        assert feature.query_name == "www.example.com"
        assert feature.normalized_name == "www.example.com"
        assert feature.source_ip == "10.0.0.5"
        assert feature.base_domain == "example.com"
        assert feature.is_query is True
        assert feature.is_null_query is False
        assert feature.is_nxdomain is False
        assert feature.is_txt_query is False

    def test_txt_query(self):
        record = make_record("data.example.com", query_type=16, query_type_name="TXT")
        feature = extract_query_features(record)
        assert feature.is_txt_query is True

    def test_null_query(self):
        record = make_record("NULL.example.com", query_type=10, query_type_name="NULL")
        feature = extract_query_features(record)
        assert feature.is_null_query is True

    def test_nxdomain_response(self):
        record = make_record(
            "missing.example.com",
            response_code=3,
            response_code_name="NXDOMAIN",
            is_query=False,
        )
        feature = extract_query_features(record)
        assert feature.is_nxdomain is True

    def test_noerror_response(self):
        record = make_record(
            "www.example.com",
            response_code=0,
            response_code_name="NOERROR",
            is_query=False,
        )
        feature = extract_query_features(record)
        assert feature.is_nxdomain is False

    def test_timestamp_from_epoch(self):
        record = make_record("www.example.com")
        record["timestamp"] = 1704110400.0
        feature = extract_query_features(record)
        assert feature.timestamp == datetime.fromtimestamp(1704110400.0)

    def test_invalid_timestamp_returns_none(self):
        record = make_record("www.example.com")
        record["timestamp"] = "not-a-date"
        feature = extract_query_features(record)
        assert feature.timestamp is None


class TestFrequencyAndBurst:
    def test_compute_frequency_empty(self):
        assert compute_frequency([]) == (0.0, 0.0, 0.0)

    def test_frequency_single_timestamp(self):
        ts = [datetime(2024, 1, 1, 12, 0, 0)]
        baseline, peak, ratio = compute_frequency(ts)
        assert baseline > 0
        assert peak > 0

    def test_steady_rate_frequency(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        ts = [base + timedelta(seconds=i * 0.05) for i in range(60)]
        baseline, peak, ratio = compute_frequency(ts)
        assert baseline > 1000
        assert peak > 0

    def test_burst_produces_ratio_greater_than_one(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        ts = [base + timedelta(seconds=i * 0.1) for i in range(40)]
        ts += [base + timedelta(seconds=10 + i * 1.5) for i in range(40)]
        baseline, peak, ratio = compute_frequency(ts)
        assert ratio > 1.0

    def test_burst_window_counts_peak(self):
        base = datetime(2024, 1, 1, 12, 0, 0)
        ts = [base + timedelta(seconds=i * 0.1) for i in range(40)]
        _, peak, _ = compute_frequency(ts, burst_window_seconds=10)
        assert peak == pytest.approx(240.0)


class TestGroupingAndFeatures:
    def test_group_by_source_and_domain(self):
        features = [
            extract_query_features(make_record(f"www{i}.example.com", source_ip="1.1.1.1"))
            for i in range(3)
        ]
        features += [
            extract_query_features(make_record(f"www{i}.other.org", source_ip="1.1.1.1"))
            for i in range(2)
        ]
        features += [
            extract_query_features(make_record(f"www{i}.example.com", source_ip="2.2.2.2"))
            for i in range(2)
        ]
        groups = group_by_source_and_domain(features)
        assert len(groups) == 3

    def test_unique_subdomain_count(self):
        records = [make_record(f"label{i}.example.com") for i in range(5)]
        features = [f for f in (extract_query_features(r) for r in records) if f]
        group = extract_group_features(features)
        assert group.unique_subdomain_count == 5

    def test_unique_subdomain_count_deduplicated(self):
        records = [make_record("label.example.com") for _ in range(5)]
        features = [f for f in (extract_query_features(r) for r in records) if f]
        group = extract_group_features(features)
        assert group.unique_subdomain_count == 1

    def test_group_nxdomain_ratio(self):
        records = []
        for i in range(4):
            records.append(
                make_record(
                    f"label{i}.example.com",
                    response_code=3,
                    response_code_name="NXDOMAIN",
                    is_query=False,
                )
            )
        records.append(
            make_record(
                "www.example.com",
                response_code=0,
                response_code_name="NOERROR",
                is_query=False,
            )
        )
        features = [f for f in (extract_query_features(r) for r in records) if f]
        group = extract_group_features(features)
        assert group.nxdomain_count == 4
        assert group.nxdomain_ratio == pytest.approx(0.8)

    def test_group_empty(self):
        group = extract_group_features([])
        assert group.query_count == 0
        assert group.queries_per_minute == 0.0
        assert group.nxdomain_ratio == 0.0

    def test_extract_features_returns_groups(self):
        records = [make_record(f"www{i}.example.com") for i in range(3)]
        groups = extract_features(records)
        assert len(groups) == 1
        group = groups[0]
        assert isinstance(group, DNSGroupFeature)
        assert group.query_count == 3
        assert group.base_domain == "example.com"


class TestMalformedInput:
    def test_empty_query_name_skipped(self):
        records = [make_record("www.example.com"), make_record("")]
        features = extract_features(records)
        assert len(features) == 1
        assert features[0].query_count == 1

    def test_none_query_name_skipped(self):
        record = make_record("www.example.com")
        record["query_name"] = None
        assert extract_features([record]) == []

    def test_record_missing_keys_no_crash(self):
        record = {"source_ip": "1.1.1.1"}
        assert extract_features([record]) == []

    def test_extract_query_features_none_for_empty_name(self):
        assert extract_query_features({"query_name": ""}) is None
        assert extract_query_features({}) is None

    def test_malformed_group_never_raises(self):
        records = [
            {},
            {"query_name": None},
            {"query_name": ""},
            make_record(".."),
        ]
        groups = extract_features(records)
        assert isinstance(groups, list)


class TestSessionExtraction:
    def _make_completed_session(self, db, query_dicts):
        session = create_session(db, "test.pcap", "original.pcap")
        save_dns_queries(db, session.id, make_dns_records(query_dicts))
        update_session_completed(
            db,
            session.id,
            total_packets=len(query_dicts),
            dns_packets=len(query_dicts),
            queries_extracted=len(query_dicts),
            processing_duration_ms=10,
            status=ProcessingStatus.COMPLETED,
        )
        return session

    def test_extract_features_for_session(self, db):
        base = datetime(2024, 1, 1, 12, 0, 0)
        query_dicts = [
            {
                "source_ip": "192.168.1.100",
                "query_name": f"label{i}.example.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "timestamp": make_ts(base, i),
            }
            for i in range(5)
        ]
        session = self._make_completed_session(db, query_dicts)

        groups = extract_features_for_session(db, session.id)

        assert len(groups) == 1
        group = groups[0]
        assert group.source_ip == "192.168.1.100"
        assert group.base_domain == "example.com"
        assert group.query_count == 5
        assert group.unique_subdomain_count == 5
        assert len(group.queries) == 5

    def test_extract_features_for_session_multiple_groups(self, db):
        base = datetime(2024, 1, 1, 12, 0, 0)
        query_dicts = [
            {
                "source_ip": src,
                "query_name": f"www{i}.{domain}",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "timestamp": make_ts(base, i),
            }
            for i, (src, domain) in enumerate(
                [("1.1.1.1", "example.com"), ("2.2.2.2", "example.com"), ("1.1.1.1", "other.org")]
            )
        ]
        session = self._make_completed_session(db, query_dicts)

        groups = extract_features_for_session(db, session.id)

        assert len(groups) == 3

    def test_extract_features_for_session_no_queries(self, db):
        session = self._make_completed_session(db, [])
        assert extract_features_for_session(db, session.id) == []

    def test_queries_persisted_and_readable(self, db):
        base = datetime(2024, 1, 1, 12, 0, 0)
        query_dicts = [
            {
                "source_ip": "192.168.1.100",
                "query_name": "www.example.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "timestamp": make_ts(base, 0),
            }
        ]
        session = self._make_completed_session(db, query_dicts)

        groups = extract_features_for_session(db, session.id)
        query = groups[0].queries[0]
        assert query.query_name == "www.example.com"
        assert query.base_domain == "example.com"


class TestFeaturesAPI:
    def _create_tunnel_pcap_bytes(self):
        packets = []
        t = 1704110400.0
        for i in range(30):
            label = base64.b32encode(os.urandom(35)).decode().lower()
            qname = f"{label}.tunnel.example.com."
            pkt = (
                Ether()
                / IP(src="192.168.1.100", dst="8.8.8.8")
                / UDP(sport=50000 + i, dport=53)
                / DNS(id=i, qr=0, qd=DNSQR(qname=qname.encode(), qtype=16 if i < 5 else 1))
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

    def _upload_tunnel_pcap(self, client):
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("tunnel.pcap", self._create_tunnel_pcap_bytes(), "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 200
        return response.json()

    def test_features_endpoint_success(self, client):
        upload = self._upload_tunnel_pcap(client)
        session_uuid = upload["session_id"]

        response = client.get(f"/api/analysis/{session_uuid}/features")

        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_uuid
        assert data["total_queries"] == 30
        assert data["group_count"] >= 1

        group = data["groups"][0]
        assert group["base_domain"] == "example.com"
        assert group["query_count"] == 30
        assert group["unique_subdomain_count"] > 0
        assert group["queries_per_minute"] > 0
        assert len(group["queries"]) == 30

        query = group["queries"][0]
        assert query["normalized_name"].endswith(".example.com")
        assert query["entropy"] >= 0
        assert "encoding_types" in query

    def test_features_endpoint_nonexistent_session(self, client):
        response = client.get("/api/analysis/nonexistent-uuid/features")
        assert response.status_code == 404

    def test_features_endpoint_not_completed(self, client, db):
        session = create_session(db, "pending.pcap", "pending.pcap")
        response = client.get(f"/api/analysis/{session.session_id}/features")
        assert response.status_code == 400
        assert "not ready" in response.json()["detail"].lower()

    def test_features_endpoint_completed_no_queries(self, client, db):
        session = create_session(db, "empty.pcap", "empty.pcap")
        update_session_completed(
            db,
            session.id,
            total_packets=0,
            dns_packets=0,
            queries_extracted=0,
            processing_duration_ms=10,
            status=ProcessingStatus.COMPLETED,
        )
        response = client.get(f"/api/analysis/{session.session_id}/features")
        assert response.status_code == 200
        data = response.json()
        assert data["total_queries"] == 0
        assert data["groups"] == []