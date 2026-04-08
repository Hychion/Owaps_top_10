# ============================================================
# OWASP Tester — Makefile (OWASP Top 10 aligned)
# ============================================================

.DEFAULT_GOAL := help
.PHONY: help build build-release test test-unit test-integration \
        lab-build lab-up lab-down lab-logs lab-status \
        lint fmt fmt-check coverage coverage-ci clean clean-docker \
        scan-a01 scan-a02 scan-a03 scan-a05 scan-a07 scan-a10 scan-all

COMPOSE      := docker compose
COMPOSE_TEST := docker compose -f docker-compose.test.yml
CARGO        := cargo

# ── Help ─────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  OWASP Tester — Make targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  Labs:"
	@echo "    A01:2021 Broken Access Control  → http://localhost:8081"
	@echo "    A02:2021 Cryptographic Failures → http://localhost:8082"
	@echo "    A03:2021 Injection              → http://localhost:8083"
	@echo "    A05:2021 Security Misconfig     → http://localhost:8085"
	@echo "    A07:2021 Auth Failures          → http://localhost:8087"
	@echo "    A10:2021 SSRF                   → http://localhost:8090"
	@echo ""

# ── Build ────────────────────────────────────────────────────────────────────

build: ## Build in debug mode
	$(CARGO) build

build-release: ## Build optimized release binary
	$(CARGO) build --release

# ── Tests ────────────────────────────────────────────────────────────────────

test: test-unit ## Run all unit tests (no Docker required)

test-unit: ## Run unit tests only (wiremock, no real network)
	$(CARGO) test --lib -- --test-threads=4

test-integration: lab-build ## Build lab images then run integration tests
	$(CARGO) test --features integration-tests -- --test-threads=1 --nocapture

# ── Lint & Format ────────────────────────────────────────────────────────────

lint: ## Run clippy with zero-warnings policy
	$(CARGO) clippy -- -D warnings

fmt: ## Format source code
	$(CARGO) fmt

fmt-check: ## Check formatting without modifying (CI)
	$(CARGO) fmt --check

# ── Coverage ─────────────────────────────────────────────────────────────────

coverage: ## Generate HTML coverage report (requires cargo-llvm-cov)
	$(CARGO) llvm-cov --lib --html --output-dir coverage/
	@echo "Report: coverage/index.html"

coverage-ci: ## Generate lcov coverage (CI)
	$(CARGO) llvm-cov --lib --lcov --output-path lcov.info

# ── Docker Labs ───────────────────────────────────────────────────────────────

lab-build: ## Build all OWASP Top 10 Docker lab images
	@echo "Building lab images..."
	docker build -t owasp-lab-a01:test docker/lab-a01
	docker build -t owasp-lab-a02:test docker/lab-a02
	docker build -t owasp-lab-a03:test docker/lab-a03
	docker build -t owasp-lab-a05:test docker/lab-a05
	docker build -t owasp-lab-a07:test docker/lab-a07
	docker build -t owasp-lab-a10:test docker/lab-a10
	@echo "Done."

lab-up: lab-build ## Start all lab containers
	$(COMPOSE) up -d
	@echo ""
	@echo "  A01:2021 Broken Access Control  → http://localhost:8081"
	@echo "  A02:2021 Cryptographic Failures → http://localhost:8082"
	@echo "  A03:2021 Injection (SQLi+XSS)   → http://localhost:8083"
	@echo "  A05:2021 Security Misconfig     → http://localhost:8085"
	@echo "  A07:2021 Auth Failures          → http://localhost:8087"
	@echo "  A10:2021 SSRF                   → http://localhost:8090"
	@echo ""

lab-down: ## Stop and remove all lab containers
	$(COMPOSE) down
	$(COMPOSE_TEST) down 2>/dev/null || true

lab-logs: ## Tail logs from all labs
	$(COMPOSE) logs -f

lab-status: ## Show health status of all labs
	@docker ps --filter "name=owasp-lab" \
		--format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

# ── Scan shortcuts ────────────────────────────────────────────────────────────

scan-a01: build ## Scan A01:2021 (Broken Access Control) against lab-a01
	./target/debug/owasp-tester scan --target http://localhost:8081 --modules "A01:2021"

scan-a02: build ## Scan A02:2021 (Cryptographic Failures) against lab-a02
	./target/debug/owasp-tester scan --target http://localhost:8082 --modules "A02:2021"

scan-a03: build ## Scan A03:2021 (Injection) against lab-a03
	./target/debug/owasp-tester scan --target http://localhost:8083 --modules "A03:2021"

scan-a05: build ## Scan A05:2021 (Security Misconfig) against lab-a05
	./target/debug/owasp-tester scan --target http://localhost:8085 --modules "A05:2021"

scan-a07: build ## Scan A07:2021 (Auth Failures) against lab-a07
	./target/debug/owasp-tester scan --target http://localhost:8087 --modules "A07:2021"

scan-a10: build ## Scan A10:2021 (SSRF) against lab-a10
	./target/debug/owasp-tester scan --target http://localhost:8090 --modules "A10:2021"

scan-all: build ## Run all modules against all labs sequentially
	@echo "=== A01 ===" && ./target/debug/owasp-tester scan --target http://localhost:8081 --modules "A01:2021"
	@echo "=== A02 ===" && ./target/debug/owasp-tester scan --target http://localhost:8082 --modules "A02:2021"
	@echo "=== A03 ===" && ./target/debug/owasp-tester scan --target http://localhost:8083 --modules "A03:2021"
	@echo "=== A05 ===" && ./target/debug/owasp-tester scan --target http://localhost:8085 --modules "A05:2021"
	@echo "=== A07 ===" && ./target/debug/owasp-tester scan --target http://localhost:8087 --modules "A07:2021"
	@echo "=== A10 ===" && ./target/debug/owasp-tester scan --target http://localhost:8090 --modules "A10:2021"

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean: ## Remove build artifacts and reports
	$(CARGO) clean
	rm -f reports/*.json reports/*.html lcov.info
	rm -rf coverage/

clean-docker: ## Remove all lab Docker images and containers
	$(COMPOSE) down --rmi local -v 2>/dev/null || true
	docker rmi owasp-lab-a01:test owasp-lab-a02:test owasp-lab-a03:test \
	           owasp-lab-a05:test owasp-lab-a07:test owasp-lab-a10:test 2>/dev/null || true
