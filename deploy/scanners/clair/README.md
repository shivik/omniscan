# Clair — container-image SCA

[Clair](https://github.com/quay/clair) is the open-source container-vulnerability engine
from Quay/Red Hat. The OmniScan `clair` adapter scans a **built container image** by
reference (`source.type = "image"`), complementing `trivy` (which scans source manifests).

## Run the Clair service (provision once)

```bash
docker compose -f deploy/scanners/clair/docker-compose.yml up -d
# first start pulls advisory feeds — several GB, takes a while to become useful
export OMNISCAN_CLAIR_URL=http://host.docker.internal:6060
```

## Build the clairctl client image (used by the adapter)

```bash
docker build -t omniscan/clairctl:0.1.0 deploy/scanners/clair
```

## Scan an image

```bash
# via API
curl -X POST localhost:8000/api/v1/scans -H "Authorization: Bearer dev-admin-token" \
  -H "Content-Type: application/json" \
  -d '{"scan_class":"SAST","project_id":"<proj_id>",
       "source":{"type":"image","image":"alpine:3.18"},
       "tools":["clair"],
       "options":{"clair_host":"http://host.docker.internal:6060"}}'
```

The adapter runs `clairctl report --out json <image>` against the Clair host and converts
the VulnerabilityReport to SARIF → Findings (severity from Clair's `normalized_severity`,
located by image/package/installed-version/fixed-version).

> Standing up Clair (service + Postgres + GBs of feeds) is heavy, so the **live** scan is
> not run by the OmniScan test suite — the report→SARIF normalization is covered by a
> contract test (`tests/adapters/test_clair.py`). This compose stack is for real use.
