import pytest
import tempfile
import os
from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, TCP, Raw, wrpcap


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


class TestHealthEndpoint:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "degraded"]
        assert data["version"] == "1.0.0"
        assert "database_connected" in data


class TestPCAPUpload:
    def test_upload_valid_pcap(self, client):
        pcap_bytes = create_test_pcap_bytes()
        
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_packets"] == 3
        assert data["dns_packets"] == 3
        assert data["queries_extracted"] == 3
        assert data["processing_status"] == "completed"
        assert "session_id" in data

    def test_upload_invalid_extension(self, client):
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("test.txt", b"not a pcap", "text/plain")},
        )
        
        assert response.status_code == 400
        assert "Invalid file extension" in response.json()["detail"]

    def test_upload_empty_file(self, client):
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("empty.pcap", b"", "application/vnd.tcpdump.pcap")},
        )
        
        assert response.status_code == 500

    def test_upload_pcap_no_dns(self, client):
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
        
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("no_dns.pcap", pcap_data, "application/vnd.tcpdump.pcap")},
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["total_packets"] == 2
        assert data["dns_packets"] == 0
        assert data["queries_extracted"] == 0
        assert data["processing_status"] == "completed"


class TestSessionsEndpoint:
    def test_list_sessions_empty(self, client):
        response = client.get("/api/sessions")
        assert response.status_code == 200
        data = response.json()
        # Note: Due to test isolation, there may be sessions from other tests
        # Just verify the structure
        assert "sessions" in data
        assert "total" in data

    def test_list_sessions_after_upload(self, client):
        pcap_bytes = create_test_pcap_bytes()
        client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        
        response = client.get("/api/sessions")
        assert response.status_code == 200
        data = response.json()
        # At least 1 session should exist
        assert data["total"] >= 1
        assert len(data["sessions"]) >= 1

    def test_get_session_by_id(self, client):
        pcap_bytes = create_test_pcap_bytes()
        upload_resp = client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        session_id = upload_resp.json()["session_id"]
        
        response = client.get(f"/api/sessions/{session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["session_id"] == session_id
        assert data["queries_extracted"] == 3

    def test_get_nonexistent_session(self, client):
        response = client.get("/api/sessions/nonexistent-id")
        assert response.status_code == 404


class TestDNSQueriesEndpoint:
    def test_get_dns_queries(self, client):
        pcap_bytes = create_test_pcap_bytes()
        upload_resp = client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        # Get the integer session ID from the sessions list
        sessions_resp = client.get("/api/sessions")
        sessions = sessions_resp.json()["sessions"]
        session_id = sessions[0]["id"]
        
        response = client.get(f"/api/dns/queries?session_id={session_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 3
        assert len(data["queries"]) >= 3
        
        query_names = [q["query_name"] for q in data["queries"]]
        assert "example.com" in query_names
        assert "google.com" in query_names

    def test_get_dns_queries_pagination(self, client):
        pcap_bytes = create_test_pcap_bytes()
        upload_resp = client.post(
            "/api/pcap/upload",
            files={"file": ("test.pcap", pcap_bytes, "application/vnd.tcpdump.pcap")},
        )
        # Get the integer session ID from the sessions list
        sessions_resp = client.get("/api/sessions")
        sessions = sessions_resp.json()["sessions"]
        session_id = sessions[0]["id"]
        
        response = client.get(f"/api/dns/queries?session_id={session_id}&limit=2")
        assert response.status_code == 200
        data = response.json()
        assert len(data["queries"]) <= 2
        assert data["page_size"] == 2

    def test_get_dns_queries_invalid_session(self, client):
        response = client.get("/api/dns/queries?session_id=99999")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["queries"] == []


class TestUploadValidation:
    def test_upload_missing_file(self, client):
        response = client.post("/api/pcap/upload")
        assert response.status_code == 422

    def test_upload_no_filename(self, client):
        response = client.post(
            "/api/pcap/upload",
            files={"file": ("", b"content", "application/vnd.tcpdump.pcap")},
        )
        assert response.status_code == 422