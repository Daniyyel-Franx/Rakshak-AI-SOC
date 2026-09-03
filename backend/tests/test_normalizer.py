from app.services import ocsf, scenario_engine
from app.services.normalizer import compute_fingerprint, normalize


def test_ocsf_core_fields_present():
    ev = ocsf.build_authentication(
        event_id="T-1", time="2026-01-15T02:00:00+00:00", user="u", src_ip="1.2.3.4",
        src_host="h", dst_host="d", success=False, site_id="site-01", scenario_id="TEST")
    for field in ("time", "activity_id", "category_uid", "class_uid", "type_uid",
                  "metadata", "severity_id", "status_id", "message", "unmapped"):
        assert field in ev, f"missing OCSF field {field}"
    # defence extensions live under unmapped
    for field in ("site_id", "asset_criticality", "mission_state", "scenario_id"):
        assert field in ev["unmapped"]


def test_type_uid_derivation():
    ev = ocsf.build_network_activity(
        event_id="T-2", time="2026-01-15T02:00:00+00:00", src_ip="1.1.1.1", dst_ip="2.2.2.2",
        dst_port=443, protocol="tcp", bytes_out=1, bytes_in=1, duration_ms=1,
        site_id="s", scenario_id="TEST")
    assert ev["type_uid"] == ev["class_uid"] * 100 + ev["activity_id"]


def test_normalize_is_deterministic():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")[0]
    a = normalize(ev)
    b = normalize(ev)
    assert a.fingerprint == b.fingerprint
    assert a.event_class == "authentication"
    assert a.site_id == "site-01"


def test_fingerprint_ignores_event_id():
    ev = scenario_engine.build_events("SCENARIO_1_SSH_COMPROMISE")[0]
    fp1 = compute_fingerprint(ev)
    ev2 = dict(ev)
    ev2["event_id"] = "DIFFERENT-ID"
    fp2 = compute_fingerprint(ev2)
    assert fp1 == fp2  # same content => same fingerprint
