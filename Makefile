# phantom-secops — quickstart targets
#
# `make demo`        — full kill-chain against the lab (requires docker compose up).
# `make demo-mock`   — same flow on canned data, no docker, no API key. CI-safe.
# `make lab-up`      — bring up the isolated docker lab.
# `make lab-down`    — tear down the lab.
# `make test`        — run pytest against tool wrappers.
# `make lint`        — basic checks (toml validation, python syntax).

.PHONY: help demo demo-mock lab-up lab-down lab-status test lint clean mcp-serve mcp-dev

help:
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

demo: lab-status  ## Run full kill-chain against the live lab
	python3 scenarios/run_kill_chain.py --target juice-shop

demo-mock:  ## Run full kill-chain on canned data (no docker, no API key)
	python3 scenarios/run_kill_chain.py --target juice-shop --mock

lab-up:  ## Start the isolated docker lab
	docker compose up -d
	@echo "→ waiting for juice-shop healthcheck..."
	@for i in $$(seq 1 30); do \
		if docker compose ps juice-shop 2>/dev/null | grep -q "(healthy)"; then \
			echo "  ✓ lab ready"; exit 0; \
		fi; \
		sleep 2; \
	done; \
	echo "  ! healthcheck timeout — see 'make lab-status'"; exit 1

lab-down:  ## Stop and remove the lab
	docker compose down -v

lab-status:  ## Show lab container status
	@docker compose ps 2>/dev/null || (echo "lab not running — run 'make lab-up'" && exit 1)

test:  ## Run tests (uses pytest if available, else unittest)
	@if python3 -c "import pytest" 2>/dev/null; then \
		python3 -m pytest tests/ -v; \
	else \
		echo "(pytest not installed — using unittest)"; \
		python3 -m unittest discover -s tests -v; \
	fi

lint:  ## Basic syntax / toml validation
	@python3 scripts/lint.py

mcp-serve:  ## Run the MCP server over stdio (for agent clients)
	python3 -m phantom_secops.mcp.server

mcp-dev:  ## Run the MCP server under the official inspector (requires mcp[cli])
	mcp dev phantom_secops/mcp/server.py

clean:  ## Remove generated reports + python cache
	rm -rf reports/runs/* reports/lab-logs/* __pycache__ .pytest_cache
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
