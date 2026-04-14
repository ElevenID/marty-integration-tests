# Makefile for Marty Integration Tests

.PHONY: help install install-e2e test test-fast test-wallet test-ui-contracts conformance conformance-crypto conformance-mdoc clean start stop restart logs

# Path to marty-core sibling repo (override with MARTY_CORE=<path>)
MARTY_CORE ?= $(realpath $(dir $(firstword $(MAKEFILE_LIST)))../marty-core)

help:
	@echo "Marty Integration Tests - Available commands:"
	@echo ""
	@echo "  make install           - Install test dependencies"
	@echo "  make install-e2e       - Install browser-test dependencies and Chromium"
	@echo "  make start             - Start all services with docker compose"
	@echo "  make stop              - Stop all services"
	@echo "  make restart           - Restart all services"
	@echo "  make test              - Run all integration tests"
	@echo "  make test-fast         - Run tests with parallel execution"
	@echo "  make test-wallet       - Run Walt.ID wallet integration tests only"
	@echo "  make test-ui-contracts - Run browser UI contract tests against a local Marty UI checkout"
	@echo "  make test-interop      - Run OID4VC wallet interoperability tests"
	@echo "  make test-eudi        - Run EUDI reference wallet/verifier interop tests"
	@echo "  make conformance       - Run OIDF OID4VC conformance tests (expects failures)"
	@echo "  make conformance-crypto - Run NIST CAVP crypto conformance (marty-core)"
	@echo "  make conformance-mdoc  - Run ISO 18013-5 mDoc conformance (marty-core)"
	@echo "  make logs              - Show service logs"
	@echo "  make clean             - Clean up containers and volumes"
	@echo ""

install:
	pip install -e ".[dev]"

install-e2e:
	pip install -e ".[dev,e2e]"
	python -m playwright install chromium

start:
	docker compose up -d
	@echo "Waiting for services to be healthy..."
	@sleep 10
	docker compose ps

stop:
	docker compose down

restart: stop start

test: start
	pytest tests/integration/ -v

test-fast: start
	pytest tests/integration/ -v -n auto

test-wallet: start
	pytest -m wallet -v

test-ui-contracts:
	pytest tests/integration/ui -v

test-marty-wallet: start
	pytest -m marty_wallet -v

test-interop: start
	pytest tests/integration/gateway/test_wallet_interop.py -v

test-eudi: start
	RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_interop.py -v

test-wallet-kit: start
	RUN_EUDI_TESTS=true pytest tests/integration/gateway/test_eudi_wallet_kit.py -v

conformance:
	@echo "Running OIDF OID4VC conformance tests through the gateway..."
	@echo "Set SESSION_ID, GATEWAY_BASE, ORG_ID, CREDENTIAL_TEMPLATE_ID env vars before running."
	@echo "Some tests WILL FAIL — they expose missing features for OIDF certification."
	pytest tests/integration/test_oid4vci_issuer_conformance.py \
		tests/integration/test_oid4vp_verifier_conformance.py \
		tests/integration/test_siop_v2_conformance.py \
		-v --no-header 2>/dev/null || true
	pytest tests/integration/test_oid4vci_issuer_conformance.py \
		tests/integration/test_oid4vp_verifier_conformance.py \
		tests/integration/test_siop_v2_conformance.py \
		-v

# ---------------------------------------------------------------------------
# Rust conformance suites (run against marty-core without docker)
# ---------------------------------------------------------------------------

# Phase 1 — NIST CAVP cryptographic primitive conformance
#   (SHA, HMAC, ECDSA, ECDH, AES-GCM, HKDF, RSA)
conformance-crypto:
	@echo "==> Crypto conformance (NIST CAVP + IETF RFCs)"
	@if [ ! -d "$(MARTY_CORE)" ]; then \
	    echo "ERROR: marty-core not found at $(MARTY_CORE). Set MARTY_CORE=<path>"; \
	    exit 1; \
	fi
	cd "$(MARTY_CORE)" && cargo test -p marty-crypto \
	    cavp_sha_hmac cavp_ecdsa cavp_ecdh cavp_aes_gcm rfc5869_hkdf cavp_rsa \
	    -- --nocapture

# Phase 2 — ISO 18013-5 mDoc + trust-chain conformance
#   (CBOR, COSE, selective disclosure, session, mdoc structure, MDL verification)
conformance-mdoc:
	@echo "==> ISO mDoc conformance (ISO 18013-5)"
	@if [ ! -d "$(MARTY_CORE)" ]; then \
	    echo "ERROR: marty-core not found at $(MARTY_CORE). Set MARTY_CORE=<path>"; \
	    exit 1; \
	fi
	cd "$(MARTY_CORE)" && cargo test -p marty-iso18013 \
	    cbor_conformance cose_conformance selective_disclosure session_conformance mdoc_structure \
	    -- --nocapture
	cd "$(MARTY_CORE)" && cargo test -p marty-verification \
	    mdl_conformance open_badges_conformance \
	    -- --nocapture

logs:
	docker compose logs -f

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage

.DEFAULT_GOAL := help
