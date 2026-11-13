# The tellagen-proxy image: one static Go binary on distroless, with the license
# text of every module inside it.
#
#   docker buildx build --build-arg VERSION=1.0.0 -t tellagen-proxy .
#
# The digests decide which image a build gets, so a new tag needs a new digest too.
ARG GO_IMAGE=golang:1.26.10-alpine@sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696
ARG BASE_IMAGE=gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd cmd
COPY internal internal
COPY protocol protocol
COPY redact redact
COPY tools tools

RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -buildvcs=false -ldflags="-s -w -X main.version=${VERSION}" -o /out/tellagen-proxy ./cmd/tellagen-proxy

# The tool runs on the build machine and reads the dependency list for the target.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -o /tmp/licenses ./tools/licenses \
    && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH /tmp/licenses -out /out/licenses ./cmd/tellagen-proxy

FROM ${BASE_IMAGE}
ARG VERSION=dev
LABEL org.opencontainers.image.title="tellagen-proxy" \
      org.opencontainers.image.description="Connects a Grafana that Tellagen cannot reach. It runs read-only queries and sends back reduced results." \
      org.opencontainers.image.vendor="Tellagen" \
      org.opencontainers.image.url="https://tellagen.com" \
      org.opencontainers.image.documentation="https://tellagen.com/help" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=build /out/tellagen-proxy /tellagen-proxy
COPY --from=build /out/licenses /licenses

EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/tellagen-proxy"]
