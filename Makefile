SHELL := /bin/sh

.DEFAULT_GOAL := verify

GO ?= go
GOFMT ?= gofmt
DOCKER ?= docker
CURL ?= curl

IMAGE ?= devsecops-supply-chain-template:local
SMOKE_PORT ?= 18080
BIN_DIR ?= bin
BINARY ?= $(BIN_DIR)/service

GO_BUILD_FLAGS := -mod=readonly -trimpath -buildvcs=false -ldflags="-s -w -buildid="
DIGEST_RESPONSE := {"algorithm":"sha256","digest":"3f412634a4ea9da04b558d0e32b0062a692e41a1c1d10f0c5c707f14440392ce"}

.PHONY: fmt fmt-check vet test test-race build verify container-build container-smoke security-test security-scan security-fixtures integrity integrity-repro signing-test release-policy-test template-test

fmt:
	@find . -type f -name '*.go' \
		! -path './.git/*' \
		! -path './$(BIN_DIR)/*' \
		-exec $(GOFMT) -w {} +

fmt-check:
	@set -eu; \
	files="$$(find . -type f -name '*.go' \
		! -path './.git/*' \
		! -path './$(BIN_DIR)/*' \
		-exec $(GOFMT) -l {} +)"; \
	if [ -n "$$files" ]; then \
		printf '%s\n' 'Go files require formatting:' "$$files"; \
		exit 1; \
	fi

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
	$(MAKE) fmt-check
	$(MAKE) vet
	$(MAKE) test
	$(MAKE) test-race
	$(MAKE) build

container-build:
	$(DOCKER) build --tag $(IMAGE) .

container-smoke:
	@set -eu; \
	container_name="devsecops-supply-chain-template-smoke-$$$$"; \
	cleanup() { \
		$(DOCKER) rm --force "$$container_name" >/dev/null 2>&1 || true; \
	}; \
	trap cleanup EXIT HUP INT TERM; \
	$(DOCKER) run --detach \
		--name "$$container_name" \
		--read-only \
		--cap-drop ALL \
		--security-opt no-new-privileges=true \
		--pids-limit 100 \
		--publish 127.0.0.1:$(SMOKE_PORT):8080 \
		$(IMAGE) >/dev/null; \
	attempt=0; \
	while :; do \
		health="$$( $(DOCKER) inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' "$$container_name" )"; \
		case "$$health" in \
			healthy) break ;; \
			unhealthy) \
				$(DOCKER) logs "$$container_name" >&2; \
				printf '%s\n' 'container became unhealthy' >&2; \
				exit 1 ;; \
		esac; \
		attempt=$$((attempt + 1)); \
		if [ "$$attempt" -ge 40 ]; then \
			$(DOCKER) logs "$$container_name" >&2; \
			printf '%s\n' 'container did not become healthy within 40 seconds' >&2; \
			exit 1; \
		fi; \
		sleep 1; \
	done; \
	runtime_user="$$( $(DOCKER) inspect --format '{{.Config.User}}' "$$container_name" )"; \
	if [ "$$runtime_user" != '65532:65532' ]; then \
		printf 'unexpected runtime user: %s\n' "$$runtime_user" >&2; \
		exit 1; \
	fi; \
	base_url='http://127.0.0.1:$(SMOKE_PORT)'; \
	health_response="$$( $(CURL) --fail --silent --show-error --max-time 3 "$$base_url/healthz" )"; \
	if [ "$$health_response" != '{"status":"ok"}' ]; then \
		printf 'unexpected health response: %s\n' "$$health_response" >&2; \
		exit 1; \
	fi; \
	digest_response="$$( $(CURL) --fail --silent --show-error --max-time 3 \
		--header 'Content-Type: application/json' \
		--data '{"value":"supply-chain"}' \
		"$$base_url/v1/digest" )"; \
	if [ "$$digest_response" != '$(DIGEST_RESPONSE)' ]; then \
		printf 'unexpected digest response: %s\n' "$$digest_response" >&2; \
		exit 1; \
	fi; \
	printf 'container smoke test passed (user=%s)\n' "$$runtime_user"

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
