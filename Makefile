.PHONY: install test eval lint run docker grep-clean
install:    ; pip install -e ".[dev]"
test:       ; pytest -q
eval:       ; python evals/adversarial_suite.py
lint:       ; ruff check .
run:        ; python examples/quickstart.py
docker:     ; docker build -t aegis . && docker run --rm aegis
# Self-audit: prove no domain-specific vocabulary leaked into the source.
grep-clean: ; ./scripts/grep-clean.sh
