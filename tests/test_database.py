import pytest
from datetime import datetime, timezone
from tests.conftest import TestingSessionLocal, engine
from app.database.database import Base
from app.models.models import AnalysisSession, DNSQuery
from app.services.database_service import (
    create_session,
    update_session_completed,
    get_session,
    get_session_by_uuid,
    list_sessions,
    count_sessions,
    save_dns_queries,
    get_dns_queries,
    count_dns_queries,
)
from app.schemas.schemas import ProcessingStatus

Base.metadata.create_all(bind=engine)


class TestDatabaseService:
    def test_create_session(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        assert session.id is not None
        assert session.session_id is not None
        assert session.filename == "test.pcap"
        assert session.original_filename == "original.pcap"
        assert session.processing_status == ProcessingStatus.PROCESSING.value
        assert session.total_packets == 0

    def test_update_session_completed(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        updated = update_session_completed(
            db,
            session.id,
            total_packets=100,
            dns_packets=50,
            queries_extracted=50,
            processing_duration_ms=1500,
            status=ProcessingStatus.COMPLETED,
        )
        
        assert updated.total_packets == 100
        assert updated.dns_packets == 50
        assert updated.queries_extracted == 50
        assert updated.processing_duration_ms == 1500
        assert updated.processing_status == ProcessingStatus.COMPLETED.value

    def test_update_session_failed(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        updated = update_session_completed(
            db,
            session.id,
            total_packets=0,
            dns_packets=0,
            queries_extracted=0,
            processing_duration_ms=100,
            status=ProcessingStatus.FAILED,
            error_message="Parse error",
        )
        
        assert updated.processing_status == ProcessingStatus.FAILED.value
        assert updated.error_message == "Parse error"

    def test_get_session(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        found = get_session(db, session.id)
        assert found is not None
        assert found.id == session.id
        
        not_found = get_session(db, 99999)
        assert not_found is None

    def test_get_session_by_uuid(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        found = get_session_by_uuid(db, session.session_id)
        assert found is not None
        assert found.session_id == session.session_id

    def test_list_sessions(self, db):
        create_session(db, "test1.pcap", "original1.pcap")
        create_session(db, "test2.pcap", "original2.pcap")
        create_session(db, "test3.pcap", "original3.pcap")
        
        sessions = list_sessions(db, skip=0, limit=10)
        assert len(sessions) == 3
        
        sessions_paginated = list_sessions(db, skip=1, limit=1)
        assert len(sessions_paginated) == 1

    def test_count_sessions(self, db):
        assert count_sessions(db) == 0
        
        create_session(db, "test1.pcap", "original1.pcap")
        assert count_sessions(db) == 1
        
        create_session(db, "test2.pcap", "original2.pcap")
        assert count_sessions(db) == 2

    def test_save_dns_queries(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        dns_records = [
            {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "transaction_id": 1234,
                "query_name": "example.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "answer_count": 1,
                "authority_count": 0,
                "additional_count": 0,
                "packet_size": 100,
                "is_query": True,
                "source_file": "test.pcap",
            },
            {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": "8.8.8.8",
                "destination_ip": "192.168.1.10",
                "transaction_id": 1234,
                "query_name": "example.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "answer_count": 1,
                "authority_count": 0,
                "additional_count": 0,
                "packet_size": 150,
                "is_query": False,
                "source_file": "test.pcap",
            },
        ]
        
        saved_count = save_dns_queries(db, session.id, dns_records)
        
        assert saved_count == 2
        
        queries = get_dns_queries(db, session.id)
        assert len(queries) == 2
        assert queries[0].query_name == "example.com"
        assert queries[0].is_query is True
        assert queries[1].is_query is False

    def test_save_empty_dns_queries(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        saved_count = save_dns_queries(db, session.id, [])
        
        assert saved_count == 0

    def test_get_dns_queries_pagination(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        dns_records = [
            {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "transaction_id": i,
                "query_name": f"test{i}.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "answer_count": 1,
                "authority_count": 0,
                "additional_count": 0,
                "packet_size": 100,
                "is_query": True,
                "source_file": "test.pcap",
            }
            for i in range(10)
        ]
        
        save_dns_queries(db, session.id, dns_records)
        
        page1 = get_dns_queries(db, session.id, skip=0, limit=3)
        assert len(page1) == 3
        
        page2 = get_dns_queries(db, session.id, skip=3, limit=3)
        assert len(page2) == 3

    def test_count_dns_queries(self, db):
        session = create_session(db, "test.pcap", "original.pcap")
        
        assert count_dns_queries(db, session.id) == 0
        
        dns_records = [
            {
                "timestamp": datetime.now(timezone.utc),
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "transaction_id": i,
                "query_name": f"test{i}.com",
                "query_type": 1,
                "query_type_name": "A",
                "response_code": 0,
                "response_code_name": "NOERROR",
                "answer_count": 1,
                "authority_count": 0,
                "additional_count": 0,
                "packet_size": 100,
                "is_query": True,
                "source_file": "test.pcap",
            }
            for i in range(5)
        ]
        
        save_dns_queries(db, session.id, dns_records)
        
        assert count_dns_queries(db, session.id) == 5