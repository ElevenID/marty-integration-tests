# Makefile for Marty Integration Tests

.PHONY: help install install-e2e stack-env test test-fast test-wallet test-ui-contracts conformance clean start stop restart logs

STACK_MANIFEST ?= stack-manifest.json

help:
	@echo "Marty Integration Tests - Available commands:"
	@echo ""
	@echo "  make install           - Install test dependencies"
	@echo "  make install-e2e       - Install browser-test dependencies and Chromium"
	@echo "  make stack-env         - Verify STACK_MANIFEST and render digest-only image inputs"
	@echo "  make start             - Start the immutable stack described by STACK_MANIFEST"
	@echo "  make stop              - Stop all services"
	@echo "  make restart           - Restart all services"
	@echo "  make test              - Run all integration tests"
	@echo "  make test-fast         - Run tests with parallel execution"
	@echo "  make test-wallet       - Run wallet integration tests only"
	@echo "  make test-ui-contracts - Run browser UI contracts against MARTY_UI_URL"
	@echo "  make test-interop      - Run OID4VC wallet interoperability tests"
	@echo "  make test-eudi         - Run EUDI reference wallet/verifier interop tests"
	@echo "  make conformance       - Run OIDF OID4VC conformance tests (expects failures)"
	@echo "  make logs              - Show service logs"
	@echo "  make clean             - Clean up containers and volumes"
	@echo ""

install:
	pip install -e ".[dev]"

install-e2e:
	pip install -e ".[dev,e2e]"
	python -m playwright install chromium

stack-env:
	python scripts/render_stack_env.py --manifest "$(STACK_MANIFEST)" --output .env.stack

start: stack-env
	docker compose --env-file .env.stack up -d
	@echo "Waiting for services to be healthy..."
	@sleep 10
	docker compose --env-file .env.stack ps

stop:
	@test -f .env.stack || { echo "ERROR: .env.stack is missing; run make stack-env first"; exit 1; }
	docker compose --env-file .env.stack down

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
	@echo "Some tests WILL FAIL - they expose missing features for OIDF certification."
	pytest tests/integration/test_oid4vci_issuer_conformance.py \
		tests/integration/test_oid4vp_verifier_conformance.py \
		tests/integration/test_siop_v2_conformance.py \
		-v --no-header 2>/dev/null || true
	pytest tests/integration/test_oid4vci_issuer_conformance.py \
		tests/integration/test_oid4vp_verifier_conformance.py \
		tests/integration/test_siop_v2_conformance.py \
		-v

logs:
	docker compose --env-file .env.stack logs -f

clean:
	@test ! -f .env.stack || docker compose --env-file .env.stack down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage

.DEFAULT_GOAL := help
