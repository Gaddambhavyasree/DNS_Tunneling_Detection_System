import pytest
import os
from pathlib import Path
from scapy.all import Ether, IP, IPv6, UDP, TCP, DNS, DNSQR, DNSRR, Raw, wrpcap
from datetime import datetime

from app.dns.parser import parse_pcap_file, extract_dns_from_packet, decode_dns_name


class TestDNSParser:
    def test_decode_dns_name_simple(self):
        name = b"example.com."
        result = decode_dns_name(name)
        assert result == "example.com"

    def test_decode_dns_name_empty(self):
        result = decode_dns_name(b"")
        assert result == ""

    def test_decode_dns_name_none(self):
        result = decode_dns_name(None)
        assert result == ""

    def test_extract_dns_query_packet(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / \
              DNS(id=0x1234, qr=0, qd=DNSQR(qname=b"example.com.", qtype=1))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        
        assert len(results) == 1
        record = results[0]
        assert record["query_name"] == "example.com"
        assert record["query_type"] == 1
        assert record["query_type_name"] == "A"
        assert record["is_query"] is True
        assert record["source_ip"] == "192.168.1.10"
        assert record["destination_ip"] == "8.8.8.8"
        assert record["transaction_id"] == 0x1234

    def test_extract_dns_response_packet(self):
        pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345) / \
              DNS(id=0x1234, qr=1, rcode=0, qd=DNSQR(qname=b"example.com.", qtype=1),
                  an=DNSRR(rrname=b"example.com.", type=1, rdata="93.184.216.34"))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        
        assert len(results) == 1
        record = results[0]
        assert record["query_name"] == "example.com"
        assert record["is_query"] is False
        assert record["response_code"] == 0
        assert record["response_code_name"] == "NOERROR"
        assert record["answer_count"] == 1

    def test_extract_dns_nxdomain(self):
        pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345) / \
              DNS(id=0x5678, qr=1, rcode=3, qd=DNSQR(qname=b"nonexistent.invalid.", qtype=1))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        
        assert len(results) == 1
        record = results[0]
        assert record["response_code"] == 3
        assert record["response_code_name"] == "NXDOMAIN"

    def test_extract_dns_aaaa_query(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / \
              DNS(id=0xabcd, qr=0, qd=DNSQR(qname=b"ipv6.google.com.", qtype=28))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        
        assert len(results) == 1
        record = results[0]
        assert record["query_type"] == 28
        assert record["query_type_name"] == "AAAA"

    def test_non_dns_packet_returns_empty(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=80) / Raw(b"HTTP")
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        
        assert len(results) == 0


class TestPCAPParsing:
    @pytest.fixture
    def sample_pcap(self, tmp_path):
        pcap_path = tmp_path / "test_dns.pcap"
        
        packets = [
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / 
            DNS(id=1, qr=0, qd=DNSQR(qname=b"example.com.", qtype=1)),
            
            Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=12345) / 
            DNS(id=1, qr=1, rcode=0, qd=DNSQR(qname=b"example.com.", qtype=1),
                an=DNSRR(rrname=b"example.com.", type=1, rdata="93.184.216.34")),
            
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12346, dport=53) / 
            DNS(id=2, qr=0, qd=DNSQR(qname=b"google.com.", qtype=28)),
            
            Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12347, dport=80) / 
            Raw(b"GET / HTTP/1.1"),
        ]
        
        wrpcap(str(pcap_path), packets)
        return pcap_path

    def test_parse_pcap_with_dns(self, sample_pcap):
        stats = parse_pcap_file(str(sample_pcap))
        
        assert stats["total_packets"] == 4
        assert stats["dns_packets"] == 3
        assert stats["queries_extracted"] == 3
        assert len(stats["dns_records"]) == 3

    def test_parse_pcap_dns_records_content(self, sample_pcap):
        stats = parse_pcap_file(str(sample_pcap))
        
        records = stats["dns_records"]
        query_names = [r["query_name"] for r in records]
        assert "example.com" in query_names
        assert "google.com" in query_names

    def test_parse_pcap_empty_file(self, tmp_path):
        empty_pcap = tmp_path / "empty.pcap"
        empty_pcap.write_bytes(b"")
        
        with pytest.raises(Exception):
            parse_pcap_file(str(empty_pcap))

    def test_parse_pcap_nonexistent_file(self):
        with pytest.raises(Exception):
            parse_pcap_file("/nonexistent/path/file.pcap")


class TestParserEdgeCases:
    def test_malformed_dns_packet(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=12345, dport=53) / \
              DNS(id=1, qr=0, qd=DNSQR(qname=b"\xc0\xff\xee", qtype=1))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        assert len(results) == 1

    def test_dns_over_tcp(self):
        pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / TCP(sport=12345, dport=53) / \
              DNS(id=1, qr=0, qd=DNSQR(qname=b"example.com.", qtype=1))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        assert len(results) == 1
        assert results[0]["query_name"] == "example.com"

    def test_ipv6_packet(self):
        pkt = Ether() / IPv6(src="2001:db8::1", dst="2001:4860:4860::8888") / UDP(sport=12345, dport=53) / \
              DNS(id=1, qr=0, qd=DNSQR(qname=b"ipv6.google.com.", qtype=28))
        
        results = extract_dns_from_packet(pkt, 0, "test.pcap")
        assert len(results) == 1
        assert results[0]["source_ip"] == "2001:db8::1"
        assert results[0]["destination_ip"] == "2001:4860:4860::8888"