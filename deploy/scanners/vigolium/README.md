# Vigolium — high-fidelity DAST

[Vigolium](https://github.com/vigolium/vigolium) is an open-source (AGPL) web
vulnerability scanner that fuses a deterministic multi-phase scan (content discovery,
spidering, active + passive auditing) with an optional LLM agentic mode.

The OmniScan `vigolium` adapter wires the **native deterministic** mode — no model, no
API key, egress scoped to the authorized target.

## Build the pinned image

```bash
# pin a digest for supply-chain integrity, e.g. VIGOLIUM_REF=sha256:<digest>
docker build -t omniscan/vigolium:0.1.0 \
  --build-arg VIGOLIUM_REF=latest deploy/scanners/vigolium
```

## Scan (DAST — requires an owned/authorized target + scope allowlist)

```bash
omniscan scan dast --project <proj_id> \
  --target https://staging.acme.test --scope-allow "*.staging.acme.test" \
  --tools vigolium --wait
```

The adapter runs `vigolium scan --target <url> --format jsonl -o /dev/stdout` and
converts the JSONL findings to SARIF, redacting URLs/evidence.

> Vigolium's **agentic** mode (`vigolium agent`) needs an LLM harness — not wired here.
> OmniScan's model-driven discovery is the open-source RVD `ollama` backend. The live
> scan isn't run by the test suite (heavy image + needs a target); the JSONL→SARIF logic
> is contract-tested in `tests/adapters/test_vigolium.py`.
