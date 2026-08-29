from scapy.all import rdpcap, DNS, DNSQR, DNSRR, IP, IPv6, UDP, TCP, Raw
from scapy.error import Scapy_Exception
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


DNS_QUERY_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}

DNS_RCODES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    6: "YXDOMAIN",
    7: "YXRRSET",
    8: "NXRRSET",
    9: "NOTAUTH",
    10: "NOTZONE",
    16: "BADVERS",
    17: "BADKEY",
    18: "BADMODE",
    19: "BADNAME",
    20: "BADALG",
    21: "BADTRUNC",
    22: "BADCOOKIE",
}


def decode_dns_name(name: bytes) -> str:
    if not name:
        return ""
    try:
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="ignore").rstrip(".")
        return str(name).rstrip(".")
    except Exception:
        return ""


def extract_dns_from_packet(packet, packet_num: int, source_file: str) -> List[Dict[str, Any]]:
    results = []
    
    if not packet.haslayer(DNS):
        return results
    
    dns_layer = packet[DNS]
    timestamp = float(packet.time) if hasattr(packet, 'time') else datetime.utcnow().timestamp()
    dt = datetime.fromtimestamp(timestamp)
    
    src_ip = None
    dst_ip = None
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif packet.haslayer(IPv6):
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    
    packet_size = len(packet)
    
    try:
        is_query = dns_layer.qr == 0
        transaction_id = dns_layer.id
        response_code = dns_layer.rcode
        response_code_name = DNS_RCODES.get(response_code, f"UNKNOWN({response_code})")
        
        query_name = None
        query_type = None
        query_type_name = None
        
        if dns_layer.qd:
            qd = dns_layer.qd
            query_name = decode_dns_name(qd.qname)
            query_type = qd.qtype
            query_type_name = DNS_QUERY_TYPES.get(query_type, f"TYPE{query_type}")
        
        answer_count = dns_layer.ancount
        authority_count = dns_layer.nscount
        additional_count = dns_layer.arcount
        
        record = {
            "timestamp": dt,
            "source_ip": src_ip,
            "destination_ip": dst_ip,
            "transaction_id": transaction_id,
            "query_name": query_name,
            "query_type": query_type,
            "query_type_name": query_type_name,
            "response_code": response_code,
            "response_code_name": response_code_name,
            "answer_count": answer_count,
            "authority_count": authority_count,
            "additional_count": additional_count,
            "packet_size": packet_size,
            "is_query": is_query,
            "source_file": source_file,
        }
        results.append(record)
        
    except Exception as e:
        logger.warning(f"Error extracting DNS from packet {packet_num}: {e}")
    
    return results


def parse_pcap_file(filepath: str) -> Dict[str, Any]:
    stats = {
        "total_packets": 0,
        "dns_packets": 0,
        "queries_extracted": 0,
        "dns_records": [],
        "errors": [],
    }
    
    try:
        packets = rdpcap(filepath)
        stats["total_packets"] = len(packets)
        
        for i, packet in enumerate(packets):
            try:
                dns_records = extract_dns_from_packet(packet, i, filepath)
                if dns_records:
                    stats["dns_packets"] += 1
                    stats["queries_extracted"] += len(dns_records)
                    stats["dns_records"].extend(dns_records)
            except Exception as e:
                stats["errors"].append(f"Packet {i}: {str(e)}")
                logger.warning(f"Error processing packet {i}: {e}")
                
    except Scapy_Exception as e:
        stats["errors"].append(f"Scapy error: {str(e)}")
        logger.error(f"Scapy error reading {filepath}: {e}")
        raise
    except Exception as e:
        stats["errors"].append(f"Unexpected error: {str(e)}")
        logger.error(f"Unexpected error reading {filepath}: {e}")
        raise
    
    return stats