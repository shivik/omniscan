# Pinned clairctl client image for the OmniScan `clair` adapter.
#
# clairctl is the official Clair v4 CLI client; it submits an image to a running Clair
# host and pulls back a VulnerabilityReport. We build it from source at a pinned tag.
# Build:  docker build -t omniscan/clairctl:0.1.0 deploy/scanners/clair
FROM golang:1.23-alpine AS build
RUN apk add --no-cache git
ARG CLAIR_VERSION=v4.8.0
RUN go install github.com/quay/clair/v4/cmd/clairctl@${CLAIR_VERSION}

FROM alpine:3.20
RUN adduser -D -u 10001 clair
COPY --from=build /go/bin/clairctl /usr/local/bin/clairctl
USER clair
ENTRYPOINT ["clairctl"]
