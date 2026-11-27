# syntax=docker/dockerfile:1

FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder

ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=0.2.6
ARG BUILD_TAGS=
ARG RELEASE_ROOTS=N1WApMUFSRF3aWP0o/ah8uIomFluMwaUTbIuP8lhhE0=

WORKDIR /src
ENV GOWORK=off

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -tags "${BUILD_TAGS}" \
      -ldflags="-s -w -X main.version=${VERSION} -X main.releaseRootsCSV=${RELEASE_ROOTS}" \
      -o /out/hopbits-agent ./cmd/hopbits-agent && \
    install -d -m 0700 -o 65532 -g 65532 /out/data

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/hopbits-agent /hopbits-agent
COPY --from=builder --chown=65532:65532 /out/data /var/lib/hopbits

VOLUME ["/var/lib/hopbits"]

USER 65532:65532
ENTRYPOINT ["/hopbits-agent"]
