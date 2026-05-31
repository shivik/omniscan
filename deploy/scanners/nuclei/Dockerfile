# Pinned nuclei DAST image with a vendored, offline template set.
#
# Build:  docker build -t omniscan/nuclei:0.1.0 deploy/scanners/nuclei
#
# DAST egress is scoped to the authorized target (SKILLS.md §3): we must NOT fetch
# the remote nuclei-templates registry at scan time. Templates are vendored here and
# the adapter runs nuclei with `-disable-update-check` + an explicit `-t` dir.
FROM projectdiscovery/nuclei:v3.8.0

COPY templates /omniscan-templates
