# Pinned semgrep scanner image for the OmniScan semgrep adapter.
#
# We vendor (pin) the upstream image rather than tracking a moving tag, and bake in
# the offline ruleset so SAST runs with no network (AGENT.md §2.3, §8.2).
# Build:  docker build -t omniscan/semgrep:0.1.0 deploy/scanners/semgrep
#
# NOTE: the dev DockerContainerRunner currently references semgrep/semgrep:1.97.0
# directly (see adapters/sast/semgrep/adapter.py::SEMGREP_IMAGE). To use this
# vendored image instead, point SEMGREP_IMAGE at omniscan/semgrep:0.1.0 and drop the
# per-scan rules mount (rules are baked in here).
FROM semgrep/semgrep:1.97.0

# Bake the version-pinned ruleset into the image.
COPY rules.yml /opt/omniscan/rules.yml

# Never fetch the registry at scan time.
ENV SEMGREP_SEND_METRICS=off \
    HOME=/tmp

# Default to the vendored offline ruleset.
ENTRYPOINT ["semgrep", "--sarif", "--config", "/opt/omniscan/rules.yml", \
            "--quiet", "--no-git-ignore", "--metrics", "off", "--disable-version-check"]
