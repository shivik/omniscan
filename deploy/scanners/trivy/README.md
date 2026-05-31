# trivy (SCA) — vendored image note

The trivy adapter references the pinned upstream image `aquasec/trivy:0.58.1` directly.
SCA is the one SAST skill permitted **limited egress** (advisory DB feeds) per
`SKILLS.md` §2 — the adapter declares `network="egress"` for that reason. To run a
fully air-gapped SCA scan, vendor the trivy DB into an image here (`trivy --download-db-only`
at build time) and run with `--skip-db-update`.
