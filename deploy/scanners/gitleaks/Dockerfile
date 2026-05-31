# Pinned gitleaks scanner image for the OmniScan gitleaks adapter.
#
# Build:  docker build -t omniscan/gitleaks:0.1.0 deploy/scanners/gitleaks
#
# gitleaks ships embedded rules, so SAST runs with no network (AGENT.md §2.3).
# The adapter (adapters/sast/gitleaks/adapter.py) references the upstream pinned tag
# directly; vendor it here if you prefer to control the supply chain.
FROM ghcr.io/gitleaks/gitleaks:v8.21.2
