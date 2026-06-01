# Pinned Vigolium image for the OmniScan `vigolium` DAST adapter.
#
# Vigolium (AGPL) is the open core of vigolium.com. We vendor the upstream image at a
# pinned reference (pin a digest for supply-chain integrity — `latest` is only the
# default placeholder here).
# Build:  docker build -t omniscan/vigolium:0.1.0 deploy/scanners/vigolium
ARG VIGOLIUM_REF=latest
FROM j3ssie/vigolium:${VIGOLIUM_REF}
# entrypoint is the `vigolium` binary (deterministic `scan` mode used by the adapter;
# the LLM `agent` mode is not used here).
