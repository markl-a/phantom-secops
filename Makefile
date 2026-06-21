# phantom-secops — quickstart targets
#
# `make demo`        — full kill-chain against the lab (requires docker compose up).
# `make demo-mock`   — same flow on canned data, no docker, no API key. CI-safe.
# `make demo-mock-mesh` — same canned flow, but DRIVEN BY A phantom-mesh AGENT
#                    LOOP (recon→vuln_scan→detect→respond via the secops_mcp
#                    façade). Needs `phantom` on PATH + CEREBRAS_API_KEY. Manual
#                    gate for M1: output is parity-equivalent to `demo-mock`.
# `make lab-up`      — bring up the isolated docker lab.
# `make lab-down`    — tear down the lab.
# `make test`        — run pytest against tool wrappers.
# `make lint`        — basic checks (toml validation, python syntax).

.PHONY: help demo demo-mock demo-mock-mesh lab-up lab-down lab-status test lint lint-mesh-config mesh-sync mesh-mcp-config clean

define MESH_MCP_CONFIG_BODY
[[mcp_servers]]
name    = "secops_recon"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_recon_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_log"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_log_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_log_ingest"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_log_ingest_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }

[[mcp_servers]]
name    = "secops_self_audit"
command = "python3"
args    = ["-m", "phantom_secops.mcp.secops_self_audit_server"]
cwd     = "$${PHANTOM_SECOPS_ROOT}"
env     = { PYTHONPATH = "$${PHANTOM_SECOPS_ROOT}" }
endef
export MESH_MCP_CONFIG_BODY

help:
	@awk 'BEGIN{FS=":.*##"} /^[a-zA-Z_-]+:.*##/ {printf "  %-14s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

demo: lab-status  ## Run full kill-chain against the live lab
	python3 scenarios/run_kill_chain.py --target juice-shop

demo-mock:  ## Run full kill-chain on canned data (no docker, no API key)
	python3 scenarios/run_kill_chain.py --target juice-shop --mock

demo-mock-mesh:  ## Agent-loop-driven kill-chain on canned data (needs phantom + CEREBRAS_API_KEY)
	python3 scenarios/run_kill_chain.py --target juice-shop --mock --driver mesh

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

mesh-sync:  ## Render agents/*.toml to phantom-mesh format and print to stdout (review then paste into mac-coord agents.toml)
	@for f in agents/red/recon.toml agents/blue/alert-triage.toml; do \
		echo "# ─── rendered from $$f ────────────────────────────────────"; \
		python3 scripts/render-mesh-agents.py $$f || exit 1; \
		echo; \
	done

mesh-mcp-config:  ## Print [[mcp_servers]] entries to paste into phantom-mesh agents.toml
	@printf '%s\n' "$$MESH_MCP_CONFIG_BODY"

lint-mesh-config:  ## Sanity check: rendered mesh-mcp-config keeps literal $${PHANTOM_SECOPS_ROOT}
	@out=$$($(MAKE) -s mesh-mcp-config); \
	echo "$$out" | grep -q '$${PHANTOM_SECOPS_ROOT}' \
	  || { echo "✗ mesh-mcp-config output is missing literal \$${PHANTOM_SECOPS_ROOT}"; echo "$$out"; exit 1; }; \
	echo "  ✓ mesh-mcp-config preserves literal \$${PHANTOM_SECOPS_ROOT}"

clean:  ## Remove generated reports + python cache
	rm -rf reports/runs/* reports/lab-logs/* __pycache__ .pytest_cache
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
