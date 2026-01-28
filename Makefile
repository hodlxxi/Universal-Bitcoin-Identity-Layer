.PHONY: help install install-dev test test-unit test-integration lint format clean coverage security pre-commit docker-build docker-up docker-down

help:
	@echo "Available commands:"
	@echo "  make install          - Install production dependencies"
	@echo "  make install-dev      - Install development dependencies"
	@echo "  make test             - Run all tests"
	@echo "  make test-unit        - Run unit tests only"
	@echo "  make test-integration - Run integration tests only"
	@echo "  make lint             - Run linting checks (flake8, mypy)"
	@echo "  make format           - Format code with black and isort"
	@echo "  make coverage         - Run tests with coverage report"
	@echo "  make security         - Run security checks (bandit, safety)"
	@echo "  make pre-commit       - Install pre-commit hooks"
	@echo "  make clean            - Clean up generated files"
	@echo "  make docker-build     - Build Docker image"
	@echo "  make docker-up        - Start development environment with docker-compose"
	@echo "  make docker-down      - Stop development environment"

install:
	pip install -r requirements.txt

install-dev:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

test:
	pytest tests/ -v

test-unit:
	pytest tests/unit/ -v

test-integration:
	pytest tests/integration/ -v

lint:
	flake8 app/ tests/ --max-line-length=120 --extend-ignore=E203,W503
	mypy app/ --ignore-missing-imports --no-strict-optional

format:
	black app/ tests/ --line-length=120
	isort app/ tests/ --profile black --line-length=120

coverage:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term
	@echo "Coverage report generated in htmlcov/index.html"

security:
	bandit -r app/ -ll
	safety check

pre-commit:
	pre-commit install
	@echo "Pre-commit hooks installed successfully"

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage coverage.xml .pytest_cache/ dist/ build/
	@echo "Cleaned up generated files"

docker-build:
	docker build -t hodlxxi:latest .

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down
