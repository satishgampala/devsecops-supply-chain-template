SHELL := /bin/sh

.DEFAULT_GOAL := verify

GO ?= go
GOFMT ?= gofmt
DOCKER ?= docker
CURL ?= curl
export GOTOOLCHAIN := $(shell awk '$$1 == "toolchain" {print $$2}' go.mod)

IMAGE ?= devsecops-supply-chain-template:local
SMOKE_PORT ?= 18080
BIN_DIR ?= bin
BINARY ?= $(BIN_DIR)/service

GO_BUILD_FLAGS := -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid="

.PHONY: fmt fmt-check toolchain-check maintenance-test vet test test-race build verify candidate container-build container-smoke security-test security-scan security-fixtures integrity integrity-repro signing-test release-policy-test template-test

fmt:
	@GOFMT=$(GOFMT) ./scripts/format-go.sh write

fmt-check:
	@GOFMT=$(GOFMT) ./scripts/format-go.sh check

toolchain-check:
	./scripts/check-toolchain.sh

maintenance-test:
	./scripts/maintenance-fixtures.sh

vet:
	$(GO) vet ./...

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -race -count=1 ./...

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build $(GO_BUILD_FLAGS) -o $(BINARY) ./cmd/service

verify:
	$(MAKE) toolchain-check
	$(MAKE) maintenance-test
	$(MAKE) fmt-check
	$(MAKE) vet
	$(MAKE) test
	$(MAKE) test-race
	$(MAKE) build

container-build:
	DOCKER=$(DOCKER) IMAGE=$(IMAGE) ./scripts/container-build.sh

candidate:
	./scripts/validate-candidate.sh

container-smoke:
	DOCKER="$(DOCKER)" CURL="$(CURL)" IMAGE="$(IMAGE)" SMOKE_PORT="$(SMOKE_PORT)" ./scripts/container-smoke.sh

security-test:
	$(GO) test -count=1 ./internal/securityreport ./cmd/sarif-normalizer ./cmd/security-gate
	./scripts/scanner-runner-fixtures.sh

security-scan:
	./scripts/security-scan.sh

security-fixtures:
	./scripts/security-fixtures.sh

integrity:
	./scripts/generate-integrity.sh

integrity-repro:
	./scripts/integrity-repro.sh

signing-test:
	$(GO) test -count=1 ./internal/signingpolicy ./cmd/signing-policy
	./scripts/signing-policy-fixtures.sh

release-policy-test:
	$(GO) test -count=1 ./internal/releasepolicy ./cmd/releaseverify
	./scripts/release-policy-fixtures.sh

template-test:
	./scripts/template-fixtures.sh
