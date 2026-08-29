import pytest
import uuid
from datetime import datetime
from app.schemas.schemas import AlertSeverity
from app.models.models import AnalysisSession, DNSQuery, DetectionResult, Alert


class TestAlertSeverityEnum:
    def test_severity_values(self):
        assert AlertSeverity.LOW.value == "LOW"
        assert AlertSeverity.MEDIUM.value == "MEDIUM"
        assert AlertSeverity.HIGH.value == "HIGH"
        assert AlertSeverity.CRITICAL.value == "CRITICAL"


class TestAlertSeverityMapping:
    def test_low_range_0_to_24(self):
        from app.dns.alert_service import AlertService

        service = AlertService()
        assert service.calculate_severity(0) == "LOW"
        assert service.calculate_severity(10) == "LOW"
        assert service.calculate_severity(24) == "LOW"

    def test_medium_range_25_to_49(self):
        from app.dns.alert_service import AlertService

        service = AlertService()
        assert service.calculate_severity(25) == "MEDIUM"
        assert service.calculate_severity(35) == "MEDIUM"
        assert service.calculate_severity(49) == "MEDIUM"

    def test_high_range_50_to_74(self):
        from app.dns.alert_service import AlertService

        service = AlertService()
        assert service.calculate_severity(50) == "HIGH"
        assert service.calculate_severity(60) == "HIGH"
        assert service.calculate_severity(74) == "HIGH"

    def test_critical_range_75_to_100(self):
        from app.dns.alert_service import AlertService

        service = AlertService()
        assert service.calculate_severity(75) == "CRITICAL"
        assert service.calculate_severity(85) == "CRITICAL"
        assert service.calculate_severity(100) == "CRITICAL"


class TestAlertServiceDeduplication:
    def test_duplicate_detection_result_id_no_new_alert(self, db):
        from app.dns.alert_service import create_alert_for_detection
        from app.dns.detection import run_detection_for_session

        db.query(DetectionResult).delete()
        db.query(AnalysisSession).delete()
        db.commit()

        session = AnalysisSession(
            session_id=str(uuid.uuid4()),
            filename="test.pcap",
            original_filename="test.pcap",
            processing_status="completed",
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        queries = [
            DNSQuery(
                session_id=session.id,
                query_name="ns1.tunnel.example.com",
                query_type=1,
                query_type_name="A",
                response_code=0,
                response_code_name="NOERROR",
                timestamp=datetime.utcnow(),
                source_ip="1.2.3.4",
                is_query=True,
            )
        ]
        db.query(DNSQuery).delete()
        db.add_all(queries)
        db.commit()

        results = run_detection_for_session(db, session.id)
        result = results[0]

        alert1 = create_alert_for_detection(db, result)
        alert2 = create_alert_for_detection(db, result)

        assert alert1 is not None
        assert alert2 is not None
        assert alert1.id == alert2.id
        assert alert1.alert_id == alert2.alert_id


class TestAlertPersistence:
    def test_alert_persisted_with_correct_fields(self, db):
        from app.dns.alert_service import create_alert_for_detection
        from app.dns.detection import run_detection_for_session

        db.query(DetectionResult).delete()
        db.query(AnalysisSession).delete()
        db.query(Alert).delete()
        db.commit()

        session = AnalysisSession(
            session_id=str(uuid.uuid4()),
            filename="test.pcap",
            original_filename="test.pcap",
            processing_status="completed",
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        queries = [
            DNSQuery(
                session_id=session.id,
                query_name="ns1.tunnel.example.com",
                query_type=1,
                query_type_name="A",
                response_code=0,
                response_code_name="NOERROR",
                timestamp=datetime.utcnow(),
                source_ip="1.2.3.4",
                is_query=True,
            )
        ]
        db.query(DNSQuery).delete()
        db.add_all(queries)
        db.commit()

        results = run_detection_for_session(db, session.id)
        result = results[0]

        alert = create_alert_for_detection(db, result)
        assert alert is not None
        assert alert.detection_result_id == result.id
        assert alert.source_ip == "1.2.3.4"
        assert alert.severity in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert alert.risk_score is not None
        assert alert.created_at is not None


class TestAlertListEndpoint:
    def test_list_alerts_returns_empty_when_no_alerts(self, client):
        response = client.get("/api/alerts?skip=0&limit=100")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["alerts"] == []


class TestAlertGetById:
    def test_get_alert_by_id_not_found(self, client):
        response = client.get("/api/alerts/99999")
        assert response.status_code == 404


class TestAlertAcknowledge:
    def test_acknowledge_alert_invalid_id(self, client):
        response = client.post("/api/alerts/99999/acknowledge", json={"acknowledged_by": "test_user"})
        assert response.status_code == 404


class TestAlertFiltering:
    def _create_test_alerts(self, db, source_ip="1.2.3.4", query_count=20):
        from app.dns.alert_service import create_alert_for_detection
        from app.dns.detection import run_detection_for_session

        db.query(DetectionResult).delete()
        db.query(AnalysisSession).delete()
        db.commit()

        session = AnalysisSession(
            session_id=str(uuid.uuid4()),
            filename="test.pcap",
            original_filename="test.pcap",
            processing_status="completed",
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        queries = [
            DNSQuery(
                session_id=session.id,
                query_name="tunnel.example.com",
                query_type=1,
                query_type_name="A",
                response_code=0,
                response_code_name="NOERROR",
                timestamp=datetime.utcnow(),
                source_ip=source_ip,
                is_query=True,
            )
            for _ in range(query_count)
        ]
        db.query(DNSQuery).delete()
        db.add_all(queries)
        db.commit()

        results = run_detection_for_session(db, session.id)
        for r in results:
            create_alert_for_detection(db, r)

    def test_list_alerts_by_severity(self, db):
        from app.dns.alert_service import AlertService

        self._create_test_alerts(db, query_count=50)

        service = AlertService()
        high_alerts = service.list_alerts(db, severity="HIGH")
        for a in high_alerts:
            assert a.severity == "HIGH"

    def test_list_alerts_by_source_ip(self, db):
        from app.dns.alert_service import AlertService

        self._create_test_alerts(db, source_ip="1.2.3.4", query_count=50)

        service = AlertService()
        alerts = service.list_alerts(db, source_ip="1.2.3.4")
        for a in alerts:
            assert a.source_ip == "1.2.3.4"

    def test_list_alerts_acknowledged_filter(self, db):
        from app.dns.alert_service import AlertService

        self._create_test_alerts(db, query_count=50)

        service = AlertService()
        all_alerts = service.list_alerts(db)
        assert len(all_alerts) > 0

        # Acknowledge first alert
        service.acknowledge_alert(db, all_alerts[0].id, "test_user")

        # Filter by acknowledged
        acknowledged = service.list_alerts(db, acknowledged=True)
        unacknowledged = service.list_alerts(db, acknowledged=False)

        assert len(acknowledged) >= 1
        assert len(unacknowledged) >= 0
        for a in acknowledged:
            assert a.acknowledged is True
        for a in unacknowledged:
            assert a.acknowledged is False