"""Integration tests through the HTTP API."""

import io
import json

import httpx
import pytest

from sentrix.core.config import Settings


def test_health_and_status_do_not_leak_secrets(client):
    assert client.get("/api/health").json()["status"] == "ok"
    s = client.get("/api/system/status").json()
    assert s["application"] == "SENTRIX AI"
    assert s["llm"]["configured"] is False
    assert "key" not in json.dumps(s["llm"]).lower().replace("api_key_required", "")


@pytest.mark.parametrize("payload", [
    {"source": "x"},                                         # no content
    {"event_type": "Failed Logon", "src_ip": "999.1.1.1"},   # bad IP
    {"event_type": "Network Connection", "dst_port": 70000},  # bad port
    {"event_type": "x" * 200},                                # too long
])
def test_event_validation(client, payload):
    r = client.post("/api/events", json=payload)
    assert r.status_code == 422
    assert r.json()["detail"] == "Validation failed"


def test_duplicate_events_are_ignored(client):
    ev = {"event_type": "Process Creation", "hostname": "dup-host", "timestamp": "2026-01-01T10:00:00Z",
          "process": "notepad.exe"}
    first = client.post("/api/events", json=ev).json()
    second = client.post("/api/events", json=ev).json()
    assert first["accepted"] == 1 and second["duplicates"] == 1 and second["accepted"] == 0


def test_ransomware_scenario_end_to_end(client, demo):
    r = client.post("/api/demo/run", json={"scenario": "ransomware"})
    assert r.status_code == 200
    body = r.json()
    assert body["events_ingested"] == 10
    assert len(body["incidents"]) == 1, "lateral movement should correlate into one incident"
    inc = client.get(f"/api/incidents/{body['incidents'][0]}").json()
    assert inc["severity"] == "critical"
    assert "Impact" in inc["tactics"] and "Lateral Movement" in inc["tactics"]
    assert {"WS-FIN-014", "FS-01", "BACKUP-01"} <= set(inc["hostnames"])
    a = inc["analysis"]
    assert set(a["agents"]) >= {"Observer", "Behavior", "Oracle", "Sentinel", "Intel", "GraphAI",
                                "DigitalTwin", "Risk", "Business"}
    assert all(p["status"] == "success" for p in a["pipeline"])
    assert a["council"]["decision"] in {c["id"] for c in a["candidates"]}
    assert a["llm"]["status"] == "skipped" or a["llm"]["status"] == "disabled"
    assert a["xai"]["decision_attribution"]
    acts = client.get(f"/api/incidents/{inc['id']}/actions").json()
    assert acts and all(x["status"] == "proposed" for x in acts)
    runs = client.get("/api/agents/runs", params={"incident_id": inc["id"]}).json()
    assert runs["total"] >= 10
    md = client.get(f"/api/incidents/{inc['id']}/report").text
    assert inc["ref"] in md and "AI Council decision" in md


def test_digital_twin_is_reproducible(client, demo):
    req = {"entry_hostnames": ["WS-FIN-014"], "playbooks": ["PB-MONITOR", "PB-ISOLATE"], "runs": 200, "seed": 3}
    a = client.post("/api/twin/simulate", json=req).json()
    b = client.post("/api/twin/simulate", json=req).json()
    assert a == b and a["status"] == "completed"
    by = {r["playbook"]: r for r in a["results"]}
    assert by["PB-ISOLATE"]["expected_compromised"] <= by["PB-MONITOR"]["expected_compromised"]
    bad = client.post("/api/twin/simulate", json={**req, "playbooks": ["PB-NOPE"]})
    assert bad.status_code == 422


def test_attack_graph_paths(client, demo):
    g = client.get("/api/graph/enterprise").json()
    assert g["paths"], "internet-facing assets should expose paths"
    assert any(n["id"] == "INTERNET" for n in g["graph"]["nodes"])


def test_approval_workflow_and_audit(client, demo):
    client.post("/api/demo/run", json={"scenario": "web_exfiltration"})
    acts = client.get("/api/actions", params={"status": "proposed"}).json()["items"]
    high = next(a for a in acts if a["risk_level"] == "high")
    low = next(a for a in acts if a["risk_level"] == "low")
    r = client.post(f"/api/actions/{high['id']}/review", json={"decision": "approve"})
    assert r.status_code == 409 and "justification" in r.json()["detail"]
    r = client.post(f"/api/actions/{high['id']}/review",
                    json={"decision": "approve", "note": "Confirmed with app owner"})
    assert r.status_code == 200 and r.json()["status"] == "pending_manual"
    assert r.json()["reviewed_by"] == "pytest-analyst"
    assert client.post(f"/api/actions/{high['id']}/review", json={"decision": "reject"}).status_code == 409
    assert client.post(f"/api/actions/{high['id']}/complete", json={"body": "done"}).json()["status"] == "completed"
    assert client.post(f"/api/actions/{low['id']}/review", json={"decision": "reject"}).json()["status"] == "rejected"
    audit = client.get("/api/audit", params={"action": "action.approve"}).json()
    assert audit["total"] >= 1 and audit["items"][0]["actor"] == "pytest-analyst"
    denied = client.get("/api/audit", params={"action": "action.approve"}).json()["items"]
    assert any(i["outcome"] == "denied" for i in denied)
    csv_text = client.get("/api/audit/export.csv").text
    assert csv_text.startswith("id,timestamp,actor")


def test_incident_update_and_notes(client, demo):
    inc = client.get("/api/incidents").json()["items"][0]
    r = client.patch(f"/api/incidents/{inc['id']}", json={"status": "contained", "assignee": "lead-1"})
    assert r.status_code == 200 and r.json()["status"] == "contained"
    assert client.patch(f"/api/incidents/{inc['id']}", json={"status": "bogus"}).status_code == 422
    n = client.post(f"/api/incidents/{inc['id']}/notes", json={"body": "Isolated via EDR"})
    assert n.status_code == 201
    detail = client.get(f"/api/incidents/{inc['id']}").json()
    assert detail["notes"][-1]["body"] == "Isolated via EDR"
    filtered = client.get("/api/incidents", params={"status": "contained"}).json()
    assert any(i["id"] == inc["id"] for i in filtered["items"])


def test_rag_retrieval_and_llm_disabled(client):
    r = client.post("/api/intel/search", json={"query": "T1486 data encrypted ransomware", "synthesize": True})
    body = r.json()
    assert body["documents"][0]["doc_id"] == "T1486"
    assert body["llm"]["status"] == "disabled"
    assert body["answer_method"] == "extractive"
    doc = {"doc_id": "CUSTOM-1", "doc_type": "custom", "title": "Internal advisory",
           "body": "Our VPN appliances must be patched within 24 hours of a KEV listing."}
    assert client.post("/api/intel/documents", json=doc).status_code == 201
    assert client.post("/api/intel/documents", json=doc).status_code == 409
    hits = client.post("/api/intel/search", json={"query": "VPN appliances patched KEV"}).json()["documents"]
    assert hits[0]["doc_id"] == "CUSTOM-1"
    assert client.delete("/api/intel/documents/CUSTOM-1").status_code == 200


def test_import_cisa_kev_feed(client):
    feed = {"vulnerabilities": [{"cveID": "CVE-2099-0001", "vendorProject": "Acme", "product": "Widget",
                                 "vulnerabilityName": "Test vuln", "dateAdded": "2099-01-01",
                                 "shortDescription": "desc", "requiredAction": "patch",
                                 "knownRansomwareCampaignUse": "Unknown"}]}
    r = client.post("/api/intel/import", params={"kind": "cisa_kev"},
                    files={"file": ("kev.json", json.dumps(feed), "application/json")})
    assert r.status_code == 200 and r.json()["added"] == 1


def test_upload_jsonl_with_raw_windows_events(client):
    lines = "\n".join(json.dumps({"EventID": 4625, "Computer": "UP-01", "TimeCreated": f"2026-02-01T10:0{i}:00Z",
                                  "EventData": {"TargetUserName": "eve", "IpAddress": "192.0.2.5"}})
                      for i in range(3))
    r = client.post("/api/events/upload", params={"format": "windows"},
                    files={"file": ("events.jsonl", io.BytesIO(lines.encode()), "application/x-ndjson")})
    assert r.status_code == 201, r.text
    assert r.json()["accepted"] == 3
    ev = client.get("/api/events", params={"hostname": "UP-01"}).json()
    assert ev["total"] == 3 and ev["items"][0]["mitre_technique"] == "T1110"


def test_assets_crud_and_validation(client):
    r = client.post("/api/assets", json={"hostname": "new-srv", "ip_address": "10.9.9.9", "criticality": "high"})
    assert r.status_code == 201 and r.json()["hostname"] == "NEW-SRV"
    assert client.post("/api/assets", json={"hostname": "new-srv"}).status_code == 409
    assert client.post("/api/assets", json={"hostname": "bad host!"}).status_code == 422
    aid = r.json()["id"]
    assert client.put(f"/api/assets/{aid}", json={"criticality": "low"}).json()["criticality"] == "low"
    assert client.delete(f"/api/assets/{aid}").status_code == 200
    assert client.get(f"/api/assets/{aid}").status_code == 404


def test_users_passwords_are_hashed(client):
    r = client.post("/api/users", json={"username": "analyst1", "email": "a1@example.com",
                                        "password": "correct-horse-battery"})
    assert r.status_code == 201 and "password" not in r.text
    assert client.post("/api/users", json={"username": "x", "email": "bad", "password": "short"}).status_code == 422


def test_api_key_enforced_for_writes(client, monkeypatch):
    import sentrix.core.security as sec

    monkeypatch.setattr(sec, "get_settings", lambda: Settings(api_key="s3cret", app_env="development"))
    assert client.get("/api/health").status_code == 200
    assert client.post("/api/events", json={"event_type": "x"}).status_code == 401
    ok = client.post("/api/events", json={"event_type": "Key Test", "hostname": "k1"},
                     headers={"X-API-Key": "s3cret"})
    assert ok.status_code == 201


def test_llm_narrative_with_mocked_provider(client, demo, monkeypatch):
    import sentrix.llm.client as llm_mod

    fake = Settings(llm_provider="anthropic", anthropic_api_key="test-key")
    monkeypatch.setattr(llm_mod, "get_settings", lambda: fake)
    calls = {}

    def fake_post(url, headers=None, json=None, timeout=None):
        calls["url"], calls["headers"] = url, headers
        content = {"executive_summary": "Ransomware activity.", "attack_narrative": "n",
                   "attacker_objective": "extortion", "recommended_next_steps": ["Isolate"], "open_questions": []}
        return httpx.Response(200, json={"content": [{"type": "text", "text": __import__("json").dumps(content)}]},
                              request=httpx.Request("POST", url))

    monkeypatch.setattr(llm_mod.httpx, "post", fake_post)
    inc = client.get("/api/incidents", params={"sort": "risk_score"}).json()["items"][0]
    r = client.post(f"/api/incidents/{inc['id']}/analyze", json={"use_llm": True})
    assert r.status_code == 200
    llm = r.json()["analysis"]["llm"]
    assert llm["status"] == "ok" and llm["content"]["attacker_objective"] == "extortion"
    assert calls["url"].endswith("/v1/messages") and calls["headers"]["anthropic-version"] == "2023-06-01"


def test_llm_failure_falls_back(client, demo, monkeypatch):
    import sentrix.llm.client as llm_mod

    monkeypatch.setattr(llm_mod, "get_settings",
                        lambda: Settings(llm_provider="openai", openai_api_key="bad"))

    def boom(url, **kw):
        return httpx.Response(401, json={"error": "nope"}, request=httpx.Request("POST", url))

    monkeypatch.setattr(llm_mod.httpx, "post", boom)
    inc = client.get("/api/incidents").json()["items"][0]
    r = client.post(f"/api/incidents/{inc['id']}/analyze", json={"use_llm": True})
    assert r.status_code == 200
    assert r.json()["analysis"]["llm"]["status"] == "error"
    assert r.json()["analysis"]["council"]["decision"]


def test_dashboard_and_risk(client, demo):
    d = client.get("/api/dashboard/summary").json()
    assert d["open_incidents"] >= 1 and 0 <= d["enterprise_risk"]["score"] <= 100
    t = client.get("/api/risk/trends", params={"days": 30}).json()
    assert t["tactics"]
    agents = client.get("/api/agents").json()
    assert {a["name"] for a in agents} >= {"Oracle", "DigitalTwin", "Narrator"}


def test_reset_requires_confirmation(client):
    assert client.post("/api/demo/reset", params={"confirm": "no"}).status_code == 400


def test_upload_csv_sample(client):
    from pathlib import Path

    data = (Path(__file__).resolve().parents[1] / "samples" / "sample_firewall.csv").read_bytes()
    r = client.post("/api/events/upload", files={"file": ("fw.csv", data, "text/csv")})
    assert r.status_code == 201, r.text
    assert r.json()["accepted"] == 2
