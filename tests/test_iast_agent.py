"""End-to-end test of the Python IAST runtime agent + collector.

Proves the real interactive path:
  1. the agent instruments sinks and, when a tainted request value reaches a sink,
     captures a correct source->sink event (file/line/route/param/tainted);
  2. the collector authenticates the per-session token and turns events into IAST
     Findings attached to the session's scan.
"""

from __future__ import annotations

import os

import pytest

from omniscan_iast import context
from omniscan_iast.agent import instrument, uninstrument
from omniscan_iast.reporter import BufferReporter


@pytest.fixture
def agent():
    reporter = BufferReporter()
    instrument(reporter)
    try:
        yield reporter
    finally:
        uninstrument()
        context.clear_request()


def test_agent_captures_tainted_sink(agent: BufferReporter):
    # Simulate a request whose `q` param carries an attacker value.
    context.bind_request("/run", {"q": "INJECTED_MARKER"})
    # App code passes the tainted value into a command sink. `echo` is harmless.
    os.system("echo INJECTED_MARKER >/dev/null")

    assert agent.events, "agent should have recorded a sink event"
    ev = agent.events[-1]
    assert ev["sink"] == "os.system"
    assert ev["rule_id"] == "IAST-cmd-injection"
    assert ev["tainted"] is True
    assert ev["param"] == "q"
    assert ev["route"] == "/run"
    # evidence must not leak the raw tainted value
    assert "INJECTED_MARKER" not in (ev["evidence"] or "")


def test_agent_untainted_when_no_request(agent: BufferReporter):
    context.clear_request()
    os.system("echo hello >/dev/null")
    assert agent.events[-1]["tainted"] is False


async def test_collector_ingests_events_into_findings(client):
    proj = (
        await client.post("/api/v1/projects", json={"name": "ia", "slug": f"ia-{os.getpid()}"})
    ).json()
    created = (
        await client.post(
            "/api/v1/iast/sessions", json={"project_id": proj["id"], "runtime": "python"}
        )
    ).json()
    sid, token = created["id"], created["collector_token"]

    # Agent reports a tainted command-injection flow.
    events = {
        "events": [
            {
                "sink": "os.system",
                "rule_id": "IAST-cmd-injection",
                "severity": "high",
                "file": "app/views.py",
                "line": 88,
                "function": "run_cmd",
                "route": "/run",
                "param": "q",
                "tainted": True,
                "evidence": "sink os.system reached with tainted input from 'q'",
            }
        ]
    }
    # bad token rejected
    bad = await client.post(
        f"/api/v1/iast/sessions/{sid}/events",
        json=events,
        headers={"X-OmniScan-IAST-Token": "nope"},
    )
    assert bad.status_code == 401

    # valid token ingests
    ok = await client.post(
        f"/api/v1/iast/sessions/{sid}/events", json=events, headers={"X-OmniScan-IAST-Token": token}
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["ingested"] == 1

    # re-posting the same event is idempotent (dedup by fingerprint)
    again = await client.post(
        f"/api/v1/iast/sessions/{sid}/events", json=events, headers={"X-OmniScan-IAST-Token": token}
    )
    assert again.json()["ingested"] == 0

    # the finding shows up as an IAST finding with runtime-flow location
    findings = (await client.get("/api/v1/findings", params={"scan_class": "IAST"})).json()
    assert findings
    f = findings[0]
    assert f["scan_class"] == "IAST"
    assert f["location"]["sink"] == "os.system"
    assert f["location"]["runtime_flow"] == "q → os.system"

    # finalize closes the collection scan
    fin = await client.post(f"/api/v1/iast/sessions/{sid}/finalize")
    assert fin.json()["status"] == "finalized"
