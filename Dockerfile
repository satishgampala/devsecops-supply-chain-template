FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal

ARG TARGETOS=linux
ARG TARGETARCH

RUN --network=none \
    CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOOS=$TARGETOS \
    GOARCH=$TARGETARCH \
    go build \
      -mod=readonly \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid=" \
      -o /out/service \
      ./cmd/service

FROM scratch

COPY --from=build --chown=65532:65532 /out/service /service

USER 65532:65532
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/service", "healthcheck"]
ENTRYPOINT ["/service"]
