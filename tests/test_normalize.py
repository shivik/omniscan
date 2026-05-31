from __future__ import annotations

from core.enums import ScanClass, Severity
from core.redact import redact
from normalize.finding import dedup, normalize_sarif
from normalize.fingerprint import fingerprint
from normalize.sarif import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    Region,
    Result,
    Run,
    SarifLog,
    Tool,
    ToolComponent,
)


def _result(rule="R1", uri="a.py", line=1, level="error"):
    return Result(
        ruleId=rule,
        level=level,
        message=Message(text="boom"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    artifactLocation=ArtifactLocation(uri=uri), region=Region(startLine=line)
                )
            )
        ],
    )


def _sarif(results, tool="toolA"):
    return SarifLog(runs=[Run(tool=Tool(driver=ToolComponent(name=tool)), results=results)])


def test_normalize_maps_severity_and_location():
    findings = normalize_sarif(_sarif([_result()]), ScanClass.SAST)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.high
    assert f.location["file"] == "a.py"
    assert f.sources == ["toolA"]


def test_fingerprint_stable_across_line_changes():
    # line number alone must not change the fingerprint (region line is not in key)
    fp1 = fingerprint("SAST", _result(line=1))
    fp2 = fingerprint("SAST", _result(line=99))
    assert fp1 == fp2


def test_dedup_merges_sources_and_keeps_highest_severity():
    a = normalize_sarif(_sarif([_result(level="warning")], tool="toolA"), ScanClass.SAST)
    b = normalize_sarif(_sarif([_result(level="error")], tool="toolB"), ScanClass.SAST)
    merged = dedup(a + b)
    assert len(merged) == 1
    assert set(merged[0].sources) == {"toolA", "toolB"}
    assert merged[0].severity == Severity.high


def test_redact_masks_secrets():
    payload = {
        "token": "supersecret",
        "note": "use ghp_abcdefghijklmnopqrstuvwx",
        "ref": "vault://x/y",
    }
    out = redact(payload)
    assert out["token"] == "***REDACTED***"
    assert "ghp_" not in out["note"]
    assert "vault://" not in out["ref"]
