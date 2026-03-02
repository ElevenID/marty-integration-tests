# Makefile for Marty Integration Tests

.PHONY: help install test test-fast test-wallet clean start stop restart logs

help:
	@echo "Marty Integration Tests - Available commands:"
	@echo ""
	@echo "  make install      - Install test dependencies"
	@echo "  make start        - Start all services with docker compose"
	@echo "  make stop         - Stop all services"
	@echo "  make restart      - Restart all services"
	@echo "  make test         - Run all integration tests"
	@echo "  make test-fast    - Run tests with parallel execution"
	@echo "  make test-wallet  - Run Walt.ID wallet integration tests only"
	@echo "  make logs         - Show service logs"
	@echo "  make clean        - Clean up containers and volumes"
	@echo ""

install:
	pip install -e ".[dev]"

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

test-marty-wallet: start
	pytest -m marty_wallet -v

logs:
	docker compose logs -f

clean:
	docker compose down -v
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage

.DEFAULT_GOAL := help
