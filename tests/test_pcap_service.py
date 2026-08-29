import pytest
import tempfile
import os
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, TCP, Raw, wrpcap
from tests.conftest import TestingSessionLocal, engine
from app.services.pcap_service import process_pcap_file, validate_pcap_file
from app.config import settings
from app.schemas.schemas import ProcessingStatus
from app.database.database import Base
from app.models.models import AnalysisSession

Base.metadata.create_all(bind=engine)


@pytest.fixture
def db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.rollback()
        db.close()


def create_test_pcap_bytes():
    packets = [
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / 
        DNS(id=1, qr=0, qd=DNSQR(qname=b"example.com.", qtype=1)),
        
        Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345) / 
        DNS(id=1, qr=1, rcode=0, qd=DNSQR(qname=b"example.com.", qtype=1),
            an=DNSRR(rrname=b"example.com.", type=1, rdata="93.184.216.34")),
        
        Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12346, dport=53) / 
        DNS(id=2, qr=0, qd=DNSQR(qname=b"google.com.", qtype=28)),
    ]
    
    with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
        temp_path = f.name
    
    try:
        wrpcap(temp_path, packets)
        with open(temp_path, 'rb') as f:
            pcap_data = f.read()
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
    
    return pcap_data


def create_test_pcap_file(tmp_path):
    pcap_data = create_test_pcap_bytes()
    filepath = tmp_path / "test.pcap"
    filepath.write_bytes(pcap_data)
    return filepath


class TestValidatePCAPFile:
    def test_valid_pcap_file(self, tmp_path):
        filepath = create_test_pcap_file(tmp_path)
        is_valid, error = validate_pcap_file(filepath)
        assert is_valid is True
        assert error == ""

    def test_nonexistent_file(self, tmp_path):
        filepath = tmp_path / "nonexistent.pcap"
        is_valid, error = validate_pcap_file(filepath)
        assert is_valid is False
        assert "does not exist" in error

    def test_empty_file(self, tmp_path):
        filepath = tmp_path / "empty.pcap"
        filepath.write_bytes(b"")
        is_valid, error = validate_pcap_file(filepath)
        assert is_valid is False
        assert "empty" in error.lower()

    def test_invalid_extension(self, tmp_path):
        filepath = tmp_path / "test.txt"
        filepath.write_bytes(b"not a pcap")
        is_valid, error = validate_pcap_file(filepath)
        assert is_valid is False
        assert "Invalid file extension" in error

    def test_oversized_file(self, tmp_path, monkeypatch):
        original_max = settings.MAX_UPLOAD_SIZE
        monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE", 100)
        
        filepath = tmp_path / "test.pcap"
        filepath.write_bytes(b"x" * 200)
        
        is_valid, error = validate_pcap_file(filepath)
        assert is_valid is False
        assert "exceeds maximum size" in error
        
        monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE", original_max)


class TestProcessPCAPFile:
    def test_process_valid_pcap(self, db, tmp_path):
        filepath = create_test_pcap_file(tmp_path)
        
        result = process_pcap_file(db, filepath, "original.pcap")
        
        assert result["success"] is True
        assert result["total_packets"] == 3
        assert result["dns_packets"] == 3
        assert result["queries_extracted"] == 3
        assert result["processing_status"] == ProcessingStatus.COMPLETED
        assert "session_id" in result

    def test_process_pcap_no_dns(self, db, tmp_path):
        packets = [
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=80) / 
            Raw(b"GET / HTTP/1.1"),
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12346, dport=443) / 
            Raw(b"HTTP/1.1"),
        ]
        
        with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False) as f:
            temp_path = f.name
        
        try:
            wrpcap(temp_path, packets)
            with open(temp_path, 'rb') as f:
                pcap_data = f.read()
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
        
        filepath = tmp_path / "no_dns.pcap"
        filepath.write_bytes(pcap_data)
        
        result = process_pcap_file(db, filepath, "no_dns.pcap")
        
        assert result["success"] is True
        assert result["total_packets"] == 2
        assert result["dns_packets"] == 0
        assert result["queries_extracted"] == 0
        assert result["processing_status"] == ProcessingStatus.COMPLETED

    def test_process_invalid_extension(self, db, tmp_path):
        filepath = tmp_path / "test.txt"
        filepath.write_bytes(b"not a pcap")
        
        result = process_pcap_file(db, filepath, "test.txt")
        
        assert result["success"] is False
        assert "Invalid file extension" in result["error"]

    def test_process_empty_file(self, db, tmp_path):
        filepath = tmp_path / "empty.pcap"
        filepath.write_bytes(b"")
        
        result = process_pcap_file(db, filepath, "empty.pcap")
        
        assert result["success"] is False
        assert "empty" in result["error"].lower()

    def test_process_corrupted_pcap(self, db, tmp_path):
        filepath = tmp_path / "corrupted.pcap"
        filepath.write_bytes(b"not a valid pcap file content")
        
        result = process_pcap_file(db, filepath, "corrupted.pcap")
        
        assert result["success"] is False

    def test_session_persisted_in_db(self, db, tmp_path):
        filepath = create_test_pcap_file(tmp_path)
        
        result = process_pcap_file(db, filepath, "original.pcap")
        
        session_id = result["session_id"]
        session = db.query(AnalysisSession).filter(AnalysisSession.session_id == session_id).first()
        
        assert session is not None
        assert session.total_packets == 3
        assert session.dns_packets == 3
        assert session.queries_extracted == 3
        assert session.processing_status == ProcessingStatus.COMPLETED.value

    def test_dns_queries_persisted_in_db(self, db, tmp_path):
        filepath = create_test_pcap_file(tmp_path)
        
        result = process_pcap_file(db, filepath, "original.pcap")
        
        session = db.query(AnalysisSession).filter(AnalysisSession.session_id == result["session_id"]).first()
        queries = session.dns_queries
        
        assert len(queries) == 3
        query_names = [q.query_name for q in queries]
        assert "example.com" in query_names
        assert "google.com" in query_names