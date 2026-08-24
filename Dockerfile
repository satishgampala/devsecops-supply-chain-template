FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS build

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
