"""Tests for idempotent database migrations."""
import os
import sqlite3
import pytest
from sqlmodel import Session, create_engine, select
from app import models
from app.database import init_db, settings
from app.models import Event, Incident

def test_migration_adds_source_columns(tmp_path):
    # Temporarily point settings to the tmp_path
    db_file = tmp_path / "test.db"
    db_url = f"sqlite:///{db_file}"
    original_url = settings.database_url
    settings.database_url = db_url

    # Create the old schema manually
    conn = sqlite3.connect(db_file)
    cursor = conn.cursor()
    
    cursor.execute("""
        CREATE TABLE events (
            id INTEGER PRIMARY KEY,
            event_id VARCHAR NOT NULL UNIQUE,
            event_time VARCHAR NOT NULL,
            received_time VARCHAR NOT NULL,
            site_id VARCHAR NOT NULL,
            event_class VARCHAR NOT NULL,
            activity_id INTEGER NOT NULL,
            type_uid INTEGER NOT NULL,
            severity_id INTEGER NOT NULL,
            status_id INTEGER NOT NULL,
            action VARCHAR NOT NULL,
            source_json JSON,
            destination_json JSON,
            user_json JSON,
            device_json JSON,
            process_json JSON,
            unmapped_json JSON,
            classification VARCHAR NOT NULL,
            fingerprint VARCHAR NOT NULL,
            priority INTEGER NOT NULL,
            created_at VARCHAR NOT NULL
        )
    """)
    
    cursor.execute("""
        CREATE TABLE incidents (
            id INTEGER PRIMARY KEY,
            incident_id VARCHAR NOT NULL UNIQUE,
            title VARCHAR NOT NULL,
            status VARCHAR NOT NULL,
            risk_score FLOAT NOT NULL,
            confidence FLOAT NOT NULL,
            mission_impact VARCHAR NOT NULL,
            entity_ids_json JSON,
            finding_ids_json JSON,
            graph_json JSON,
            timeline_json JSON,
            evidence_refs_json JSON,
            recommended_actions_json JSON,
            analysis_json JSON,
            scenario_id VARCHAR NOT NULL,
            created_at VARCHAR NOT NULL,
            updated_at VARCHAR NOT NULL
        )
    """)
    
    # Insert old data
    cursor.execute("""
        INSERT INTO events (event_id, event_time, received_time, site_id, event_class, activity_id, type_uid, severity_id, status_id, action, classification, fingerprint, priority, created_at)
        VALUES ('evt-1', 'time', 'time', 'site', 'class', 1, 1, 1, 1, 'action', 'class', 'finger', 1, 'time')
    """)
    cursor.execute("""
        INSERT INTO incidents (incident_id, title, status, risk_score, confidence, mission_impact, scenario_id, created_at, updated_at)
        VALUES ('inc-1', 'title', 'open', 0.0, 0.0, 'high', 'scen', 'time', 'time')
    """)
    conn.commit()
    conn.close()

    try:
        # Patch engine in database.py to point to our test DB
        import app.database as db_module
        old_engine = db_module.engine
        db_module.engine = create_engine(db_url, echo=False)
        
        # Run initialization
        db_module.init_db()
        
        # Verify columns exist and data was preserved
        with Session(db_module.engine) as session:
            evt = session.exec(select(Event).where(Event.event_id == "evt-1")).first()
            assert evt is not None
            assert evt.source == "demo"
            
            inc = session.exec(select(Incident).where(Incident.incident_id == "inc-1")).first()
            assert inc is not None
            assert inc.source == "demo"
            
            # Check idempotency - running it again shouldn't fail or wipe data
            db_module.init_db()
            evt = session.exec(select(Event).where(Event.event_id == "evt-1")).first()
            assert evt is not None
            assert evt.source == "demo"

    finally:
        # Restore original settings
        settings.database_url = original_url
        if 'old_engine' in locals():
            db_module.engine = old_engine
