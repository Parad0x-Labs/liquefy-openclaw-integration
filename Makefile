# Liquefy — AI-Agent-First Makefile
# One command to rule them all.

SHELL := /bin/bash
PYTHON := python3
VENV := .venv
VENV_BIN := $(VENV)/bin
PIP := $(VENV_BIN)/pip
PY := $(VENV_BIN)/python
PYTHONPATH_EXPORT := PYTHONPATH=tools:api

.PHONY: setup test bench quick clean help doctor self-test version \
        pack restore search scan viz archiver daemon leak-scan \
        obsidian telemetry sandbox setup-wizard \
        predict suggest prune summarize migrate score \
        openclaw-hook openclaw-status audit-verify status \
        fleet-register fleet-status fleet-quota fleet-ingest \
        fleet-merge fleet-gc fleet-heartbeat \
        compliance compliance-verify compliance-timeline \
        vision-scan vision-pack vision-restore vision-stats \
        cloud-push cloud-pull cloud-status cloud-verify

# ─── Default target ───

help: ## Show this help
	@echo ""
	@echo "  Liquefy — AI-Agent-First Compression Platform"
	@echo "  =============================================="
	@echo ""
	@echo "  SETUP"
	@echo "    make setup          One-line install (venv + deps + smoke test)"
	@echo "    make setup-wizard   Interactive setup wizard (presets, config)"
	@echo "    make doctor         Check environment health"
	@echo "    make self-test      Run engine roundtrip self-test"
	@echo "    make version        Print version info"
	@echo ""
	@echo "  CORE OPERATIONS"
	@echo "    make quick DIR=./data              Compress a directory (auto-detect everything)"
	@echo "    make pack SRC=./data OUT=./vault   Pack with explicit paths"
	@echo "    make restore SRC=./vault OUT=./out Restore from vault"
	@echo "    make search VAULT=./vault Q=error  Search compressed vaults"
	@echo ""
	@echo "  SECURITY"
	@echo "    make leak-scan DIR=./data     Deep scan for secrets/credentials"
	@echo "    make sandbox SKILL=./skill    Sandbox-test a ClawHub skill"
	@echo ""
	@echo "  MONITORING"
	@echo "    make viz VAULT=./vault        Terminal vault visualizer"
	@echo "    make viz-web VAULT=./vault    Web UI vault visualizer"
	@echo ""
	@echo "  AUTOMATION"
	@echo "    make archiver DIR=~/.openclaw Single archival sweep"
	@echo "    make daemon DIR=~/.openclaw   Start background archiver daemon"
	@echo "    make obsidian                 Sync vaults to Obsidian"
	@echo "    make telemetry FILE=data.jsonl Ingest telemetry JSONL"
	@echo ""
	@echo "  OPENCLAW NATIVE INTEGRATION"
	@echo "    make openclaw-hook            Install zero-config OpenClaw hooks"
	@echo "    make openclaw-status          Show integration status"
	@echo "    make status                   Same as openclaw-status"
	@echo ""
	@echo "  AI INTELLIGENCE"
	@echo "    make predict DIR=~/.openclaw  Predict bloat 24h/72h in advance"
	@echo "    make suggest DIR=~/.openclaw  Suggest policy tweaks"
	@echo "    make score VAULT=./vault      Value-score traces (high/med/low)"
	@echo "    make prune DIR=./vault        Smart-prune low-value traces"
	@echo "    make summarize VAULT=./vault  LLM-powered vault summary"
	@echo "    make migrate SRC=./backup.tar.gz OUT=./vault  Import from tar/zstd/gzip"
	@echo ""
	@echo "  FLEET (Multi-Agent Coordination)"
	@echo "    make fleet-register AGENT=x [QUOTA_MB=500]  Register an agent"
	@echo "    make fleet-status                           Fleet-wide dashboard"
	@echo "    make fleet-quota AGENT=x                    Check agent quota"
	@echo "    make fleet-ingest AGENT=x SRC=./data        Ingest for an agent"
	@echo "    make fleet-merge TARGET=x SOURCES='a b c'   Merge vaults across agents"
	@echo "    make fleet-gc [MAX_AGE=30]                  Fleet-wide garbage collect"
	@echo ""
	@echo "  COMPLIANCE"
	@echo "    make audit-verify                      Verify tamper-proof audit chain"
	@echo "    make compliance VAULT=./vault           Generate HTML compliance report"
	@echo "    make compliance-verify VAULT=./vault    Verify chain integrity (pass/fail)"
	@echo "    make compliance-timeline VAULT=./vault  Generate event timeline HTML"
	@echo ""
	@echo "  VISION (Screenshot Dedup — Engine #24)"
	@echo "    make vision-scan DIR=./screenshots      Scan images, report dedup potential"
	@echo "    make vision-pack DIR=./screenshots      Pack into deduplicated VSNX vault"
	@echo "    make vision-restore SRC=./vault.vsnx    Restore all images from vault"
	@echo "    make vision-stats SRC=./vault.vsnx      Show vault dedup stats"
	@echo ""
	@echo "  KEY BACKUP (Disaster Recovery)"
	@echo "    make key-backup                        Export key to encrypted backup file"
	@echo "    make key-recover SRC=./backup.enc       Recover key from backup"
	@echo "    make key-card                           Generate printable recovery card"
	@echo "    make key-verify SRC=./backup.enc        Verify backup is valid"
	@echo ""
	@echo "  ON-CHAIN ANCHORING (Solana)"
	@echo "    make vault-proof VAULT=./vault          Compute proof (free, offline)"
	@echo "    make vault-anchor VAULT=. KEYPAIR=~/.config/solana/id.json  Anchor on Solana"
	@echo "    make vault-verify VAULT=./vault         Verify vault vs anchor"
	@echo "    make vault-show PROOF=./proof.json      Display anchor proof"
	@echo ""
	@echo "  TOKEN LEDGER [EXPERIMENTAL]"
	@echo "    make token-scan DIR=./agent-output      Scan logs for token usage"
	@echo "    make token-budget ORG=acme DAILY=500000 Set token budgets"
	@echo "    make token-report ORG=acme              Usage report"
	@echo "    make token-audit DIR=./agent-output     Detect token waste"
	@echo "    make token-models                      List known models + costs"
	@echo ""
	@echo "  CONFIG GUARD (Update Protection)"
	@echo "    make guard-save DIR=./my-agent          Snapshot before update"
	@echo "    make guard-restore DIR=./my-agent       Restore after update"
	@echo "    make guard-diff DIR=./my-agent          Show what changed"
	@echo "    make guard-status DIR=./my-agent        File status overview"
	@echo ""
	@echo "  CLOUD SYNC (S3 / R2 / MinIO)"
	@echo "    make cloud-push VAULT=./vault BUCKET=x  Push vaults (encrypted) to cloud"
	@echo "    make cloud-pull VAULT=./vault BUCKET=x  Restore vaults from cloud"
	@echo "    make cloud-status VAULT=. BUCKET=x      Compare local vs remote"
	@echo "    make cloud-verify VAULT=. BUCKET=x      Verify remote integrity"
	@echo ""
	@echo "  DEVELOPMENT"
	@echo "    make test           Run full test suite (201 tests)"
	@echo "    make bench          Run compression benchmark"
	@echo "    make clean          Remove venv + cache + build artifacts"
	@echo ""
	@echo "  PRESETS (append to any pack/quick command)"
	@echo "    PRESET=safe         Default — max security, balanced speed"
	@echo "    PRESET=power        Faster, balanced policy, sampled verify"
	@echo "    PRESET=yolo         Everything included, max ratio, your risk"
	@echo ""

# ─── Setup ───

setup: ## One-line install: venv + deps + smoke test
	@echo ">>> Creating virtualenv..."
	@$(PYTHON) -m venv $(VENV) 2>/dev/null || { echo "ERROR: python3 -m venv failed. Install python3-venv."; exit 1; }
	@echo ">>> Installing dependencies..."
	@$(PIP) install --quiet --upgrade pip
	@$(PIP) install --quiet -r api/requirements.txt
	@echo ">>> Running smoke test..."
	@$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cli.py self-test --json | $(PY) -c "import sys,json; d=json.load(sys.stdin); print('SELF-TEST:', 'PASS' if d.get('ok') else 'FAIL'); sys.exit(0 if d.get('ok') else 1)" 2>/dev/null || echo "SELF-TEST: could not verify (non-blocking)"
	@echo ""
	@echo "  ✓ READY. Run 'make help' to see all commands."
	@echo "  ✓ Quick start: make quick DIR=./your/data"
	@echo ""

$(VENV):
	@$(PYTHON) -m venv $(VENV)
	@$(PIP) install --quiet --upgrade pip
	@$(PIP) install --quiet -r api/requirements.txt

# ─── Preset Resolution ───

PRESET ?= safe
VERIFY_MODE_safe := full
VERIFY_MODE_power := fast
VERIFY_MODE_yolo := full
POLICY_MODE_safe := strict
POLICY_MODE_power := balanced
POLICY_MODE_yolo := off
PROFILE_safe := default
PROFILE_power := speed
PROFILE_yolo := ratio

_VERIFY_MODE = $(VERIFY_MODE_$(PRESET))
_POLICY_MODE = $(POLICY_MODE_$(PRESET))
_PROFILE = $(PROFILE_$(PRESET))
_INCLUDE_SECRETS = $(if $(filter yolo,$(PRESET)),--include-secrets "I UNDERSTAND THIS MAY LEAK SECRETS",)

# ─── Core Operations ───

quick: $(VENV) ## Compress any directory (auto-detect format, auto-route engines)
	@test -n "$(DIR)" || { echo "Usage: make quick DIR=./path/to/data [PRESET=safe|power|yolo]"; exit 1; }
	@$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_setup.py quick "$(DIR)" \
		--profile $(_PROFILE) --verify-mode $(_VERIFY_MODE) --mode $(_POLICY_MODE) --json

pack: $(VENV) ## Pack a directory into a vault
	@test -n "$(SRC)" || { echo "Usage: make pack SRC=./data OUT=./vault [PRESET=safe|power|yolo]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/tracevault_pack.py "$(SRC)" \
		--org default --out "$(or $(OUT),./vault/$(notdir $(SRC)))" \
		--profile $(_PROFILE) --verify-mode $(_VERIFY_MODE) --mode $(_POLICY_MODE) \
		$(_INCLUDE_SECRETS) --json

restore: $(VENV) ## Restore from a vault
	@test -n "$(SRC)" || { echo "Usage: make restore SRC=./vault OUT=./restored"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/tracevault_restore.py "$(SRC)" \
		--out "$(or $(OUT),./restored/$(notdir $(SRC)))" --json

search: $(VENV) ## Search compressed vaults
	@test -n "$(VAULT)" || { echo "Usage: make search VAULT=./vault Q=search_term"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/tracevault_search.py "$(VAULT)" --query "$(or $(Q),*)"

# ─── Security ───

leak-scan: $(VENV) ## Deep scan for leaked secrets
	@test -n "$(DIR)" || { echo "Usage: make leak-scan DIR=./path/to/scan"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_leakhunter.py scan "$(DIR)" --deep --json

sandbox: $(VENV) ## Sandbox-test a ClawHub skill
	@test -n "$(SKILL)" || { echo "Usage: make sandbox SKILL=./path/to/skill"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_sandbox.py run "$(SKILL)" --timeout 60 --json

# ─── Monitoring ───

viz: $(VENV) ## Terminal vault visualizer
	@test -n "$(VAULT)" || { echo "Usage: make viz VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_viz.py timeline "$(VAULT)"

viz-web: $(VENV) ## Web UI vault visualizer
	@test -n "$(VAULT)" || { echo "Usage: make viz-web VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_viz.py web "$(VAULT)"

# ─── Automation ───

archiver: $(VENV) ## Single archival sweep
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_archiver.py once \
		--watch "$(or $(DIR),~/.openclaw)" --out "$(or $(OUT),~/.liquefy/vault)" --json

daemon: $(VENV) ## Start background archiver daemon
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_archiver.py daemon \
		--watch "$(or $(DIR),~/.openclaw)" --out "$(or $(OUT),~/.liquefy/vault)"

obsidian: $(VENV) ## Sync vaults to Obsidian
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_obsidian.py sync \
		--vault-root "$(or $(VAULT),~/.liquefy/vault)" \
		--obsidian "$(or $(OBSIDIAN),~/Obsidian)"

telemetry: $(VENV) ## Ingest telemetry JSONL
	@test -n "$(FILE)" || { echo "Usage: make telemetry FILE=data.jsonl"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_telemetry_sink.py ingest "$(FILE)" \
		--out "$(or $(OUT),./vault/telemetry)" --json

# ─── Health Checks ───

doctor: $(VENV) ## Environment health check
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cli.py doctor --json

self-test: $(VENV) ## Engine roundtrip self-test
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cli.py self-test --json

version: $(VENV) ## Print version info
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cli.py version --json

# ─── Setup Wizard ───

setup-wizard: $(VENV) ## Interactive setup wizard
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_setup.py

# ─── Development ───

test: $(VENV) ## Run full test suite
	$(PYTHONPATH_EXPORT) $(PY) -m pytest tests/ -v

bench: $(VENV) ## Run compression benchmark
	$(PYTHONPATH_EXPORT) $(PY) bench/run_format_matrix.py
	$(PYTHONPATH_EXPORT) $(PY) bench/scoreboard.py

# ─── OpenClaw Native Integration ───

openclaw-hook: $(VENV) ## Install zero-config OpenClaw hooks
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_openclaw_plugin.py hook install --create

openclaw-status: $(VENV) ## Show OpenClaw integration status
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_openclaw_plugin.py status

status: openclaw-status ## Alias for openclaw-status

# ─── AI Intelligence ───

predict: $(VENV) ## Predict workspace bloat 24h/72h in advance
	@test -n "$(DIR)" || { echo "Usage: make predict DIR=~/.openclaw"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py predict "$(DIR)"

suggest: $(VENV) ## Suggest policy tweaks based on usage patterns
	@test -n "$(DIR)" || { echo "Usage: make suggest DIR=~/.openclaw"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py suggest "$(DIR)"

score: $(VENV) ## Value-score traces (high/medium/low)
	@test -n "$(VAULT)" || { echo "Usage: make score VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py score "$(VAULT)"

prune: $(VENV) ## Smart-prune low-value traces (dry-run by default)
	@test -n "$(DIR)" || { echo "Usage: make prune DIR=./vault [--max-age 30 --min-score 0.3]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py prune "$(DIR)" --dry-run

summarize: $(VENV) ## LLM-powered vault summary
	@test -n "$(VAULT)" || { echo "Usage: make summarize VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py summarize "$(VAULT)"

migrate: $(VENV) ## Import from tar/zstd/gzip backups
	@test -n "$(SRC)" || { echo "Usage: make migrate SRC=./backup.tar.gz OUT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_intelligence.py migrate "$(SRC)" --out "$(or $(OUT),./vault/migrated)"

# ─── Compliance ───

audit-verify: $(VENV) ## Verify tamper-proof audit chain integrity
	$(PYTHONPATH_EXPORT) $(PY) -c "from liquefy_audit_chain import audit_verify; import json; print(json.dumps(audit_verify(), indent=2))"

compliance: $(VENV) ## Generate HTML compliance report from audit chain
	@test -n "$(VAULT)" || { echo "Usage: make compliance VAULT=./vault [ORG=acme] [TITLE='Q1 Audit']"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_compliance.py report \
		--vault "$(VAULT)" --output "$(or $(OUT),COMPLIANCE_REPORT.html)" \
		$(if $(ORG),--org "$(ORG)",) $(if $(TITLE),--title "$(TITLE)",)

compliance-verify: $(VENV) ## Verify audit chain integrity (pass/fail)
	@test -n "$(VAULT)" || { echo "Usage: make compliance-verify VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_compliance.py verify --vault "$(VAULT)" --json

compliance-timeline: $(VENV) ## Generate event timeline HTML
	@test -n "$(VAULT)" || { echo "Usage: make compliance-timeline VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_compliance.py timeline \
		--vault "$(VAULT)" --output "$(or $(OUT),TIMELINE.html)"

# ─── Vision (Screenshot Dedup) ───

vision-scan: $(VENV) ## Scan directory for image dedup potential
	@test -n "$(DIR)" || { echo "Usage: make vision-scan DIR=./screenshots"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vision.py scan "$(DIR)" --json

vision-pack: $(VENV) ## Deduplicate and pack images into VSNX vault
	@test -n "$(DIR)" || { echo "Usage: make vision-pack DIR=./screenshots [OUT=./vault/vision.vsnx]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vision.py pack "$(DIR)" \
		--out "$(or $(OUT),./vault/vision.vsnx)" --json

vision-restore: $(VENV) ## Restore images from VSNX vault
	@test -n "$(SRC)" || { echo "Usage: make vision-restore SRC=./vault/vision.vsnx [OUT=./restored]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vision.py restore "$(SRC)" \
		--out "$(or $(OUT),./restored)" --json

vision-stats: $(VENV) ## Show VSNX vault stats
	@test -n "$(SRC)" || { echo "Usage: make vision-stats SRC=./vault/vision.vsnx"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vision.py stats "$(SRC)" --json

# ─── Cloud Sync (S3/R2/MinIO) ───

cloud-push: $(VENV) ## Sync local vaults to S3-compatible cloud
	@test -n "$(VAULT)" || { echo "Usage: make cloud-push VAULT=./vault BUCKET=my-backups [ENDPOINT=https://...]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cloud_sync.py push \
		--vault "$(VAULT)" --bucket "$(BUCKET)" \
		$(if $(ENDPOINT),--endpoint "$(ENDPOINT)",) \
		$(if $(PREFIX),--prefix "$(PREFIX)",) --json

cloud-pull: $(VENV) ## Restore vaults from cloud
	@test -n "$(VAULT)" || { echo "Usage: make cloud-pull VAULT=./vault BUCKET=my-backups"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cloud_sync.py pull \
		--vault "$(VAULT)" --bucket "$(BUCKET)" \
		$(if $(ENDPOINT),--endpoint "$(ENDPOINT)",) \
		$(if $(PREFIX),--prefix "$(PREFIX)",) --json

cloud-status: $(VENV) ## Show local vs remote sync status
	@test -n "$(VAULT)" || { echo "Usage: make cloud-status VAULT=./vault BUCKET=my-backups"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cloud_sync.py status \
		--vault "$(VAULT)" --bucket "$(BUCKET)" \
		$(if $(ENDPOINT),--endpoint "$(ENDPOINT)",) \
		$(if $(PREFIX),--prefix "$(PREFIX)",) --json

key-backup: $(VENV) ## Export encryption key to a passphrase-protected backup
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_key_backup.py export \
		--output "$(or $(OUT),liquefy_key_backup.enc)"

key-recover: $(VENV) ## Recover encryption key from a backup file
	@test -n "$(SRC)" || { echo "Usage: make key-recover SRC=./liquefy_key_backup.enc"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_key_backup.py recover --input "$(SRC)"

key-card: $(VENV) ## Generate printable recovery card
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_key_backup.py card \
		--output "$(or $(OUT),RECOVERY_CARD.txt)"

key-verify: $(VENV) ## Verify a key backup file can be decrypted
	@test -n "$(SRC)" || { echo "Usage: make key-verify SRC=./liquefy_key_backup.enc"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_key_backup.py verify --input "$(SRC)"

# ─── On-Chain Anchoring (Solana) ───

vault-proof: $(VENV) ## Compute vault integrity proof (offline, free)
	@test -n "$(VAULT)" || { echo "Usage: make vault-proof VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vault_anchor.py proof --vault "$(VAULT)" --json

vault-anchor: $(VENV) ## Anchor vault proof on Solana (~0.000005 SOL)
	@test -n "$(VAULT)" -a -n "$(KEYPAIR)" || { echo "Usage: make vault-anchor VAULT=./vault KEYPAIR=~/.config/solana/id.json [CLUSTER=mainnet]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vault_anchor.py anchor \
		--vault "$(VAULT)" --keypair "$(KEYPAIR)" --cluster $(or $(CLUSTER),mainnet) --json

vault-verify: $(VENV) ## Verify vault matches its on-chain anchor
	@test -n "$(VAULT)" || { echo "Usage: make vault-verify VAULT=./vault"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vault_anchor.py verify --vault "$(VAULT)" --json

vault-show: $(VENV) ## Display an existing anchor proof
	@test -n "$(PROOF)" || { echo "Usage: make vault-show PROOF=./vault/.anchor-proof.json"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_vault_anchor.py show --proof "$(PROOF)" --json

# ─── Token Ledger [EXPERIMENTAL] ───

token-scan: $(VENV) ## [EXPERIMENTAL] Scan agent logs for token usage
	@test -n "$(DIR)" || { echo "Usage: make token-scan DIR=./agent-output"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_token_ledger.py scan --dir "$(DIR)" --json

token-budget: $(VENV) ## [EXPERIMENTAL] Set token budgets per org
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_token_ledger.py budget \
		--org "$(or $(ORG),default)" \
		$(if $(DAILY),--daily $(DAILY),) $(if $(MONTHLY),--monthly $(MONTHLY),) \
		$(if $(DAILY_COST),--daily-cost $(DAILY_COST),) --json

token-report: $(VENV) ## [EXPERIMENTAL] Token usage report
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_token_ledger.py report \
		--org "$(or $(ORG),default)" --period "$(or $(PERIOD),all)" \
		$(if $(DIR),--dir "$(DIR)",) --json

token-audit: $(VENV) ## [EXPERIMENTAL] Detect token waste
	@test -n "$(DIR)" || { echo "Usage: make token-audit DIR=./agent-output"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_token_ledger.py audit --dir "$(DIR)" --json

token-models: $(VENV) ## [EXPERIMENTAL] List known models and costs
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_token_ledger.py models --json

# ─── Config Guard (Update Protection) ───

guard-save: $(VENV) ## Snapshot config files before an update
	@test -n "$(DIR)" || { echo "Usage: make guard-save DIR=./my-agent [LABEL='pre-v2.0']"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_config_guard.py save \
		--dir "$(DIR)" $(if $(LABEL),--label "$(LABEL)",) --json

guard-restore: $(VENV) ## Restore customizations after an update
	@test -n "$(DIR)" || { echo "Usage: make guard-restore DIR=./my-agent"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_config_guard.py restore --dir "$(DIR)" --json

guard-diff: $(VENV) ## Show what changed since snapshot
	@test -n "$(DIR)" || { echo "Usage: make guard-diff DIR=./my-agent"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_config_guard.py diff --dir "$(DIR)" --json

guard-status: $(VENV) ## Show guarded file statuses
	@test -n "$(DIR)" || { echo "Usage: make guard-status DIR=./my-agent"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_config_guard.py status --dir "$(DIR)" --json

cloud-verify: $(VENV) ## Verify remote vault integrity against local
	@test -n "$(VAULT)" || { echo "Usage: make cloud-verify VAULT=./vault BUCKET=my-backups"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_cloud_sync.py verify \
		--vault "$(VAULT)" --bucket "$(BUCKET)" \
		$(if $(ENDPOINT),--endpoint "$(ENDPOINT)",) \
		$(if $(PREFIX),--prefix "$(PREFIX)",) --json

# ─── Fleet (Multi-Agent Coordination) ───

FLEET_ROOT ?= ~/.liquefy/fleet

fleet-register: $(VENV) ## Register an agent in the fleet
	@test -n "$(AGENT)" || { echo "Usage: make fleet-register AGENT=agent-1 [QUOTA_MB=500] [PRIORITY=10]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" register \
		--agent "$(AGENT)" --quota-mb $(or $(QUOTA_MB),0) --priority $(or $(PRIORITY),10)

fleet-status: $(VENV) ## Fleet-wide dashboard
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" status

fleet-quota: $(VENV) ## Check agent quota
	@test -n "$(AGENT)" || { echo "Usage: make fleet-quota AGENT=agent-1"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" quota --agent "$(AGENT)" --json

fleet-ingest: $(VENV) ## Ingest data for an agent (quota-enforced)
	@test -n "$(AGENT)" -a -n "$(SRC)" || { echo "Usage: make fleet-ingest AGENT=agent-1 SRC=./data"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" ingest \
		--agent "$(AGENT)" --src "$(SRC)" --profile $(_PROFILE) --verify-mode $(_VERIFY_MODE) --policy-mode $(_POLICY_MODE) --json

fleet-merge: $(VENV) ## Merge vaults from multiple agents into one
	@test -n "$(TARGET)" -a -n "$(SOURCES)" || { echo "Usage: make fleet-merge TARGET=main SOURCES='agent-1 agent-2' [STRATEGY=last_write]"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" merge \
		--target "$(TARGET)" --sources $(SOURCES) --strategy $(or $(STRATEGY),last_write) --json

fleet-gc: $(VENV) ## Fleet-wide garbage collection
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" gc \
		--max-age $(or $(MAX_AGE),0) $(if $(DRY_RUN),--dry-run,) --json

fleet-heartbeat: $(VENV) ## Update agent heartbeat
	@test -n "$(AGENT)" || { echo "Usage: make fleet-heartbeat AGENT=agent-1"; exit 1; }
	$(PYTHONPATH_EXPORT) $(PY) tools/liquefy_fleet_cli.py --fleet "$(FLEET_ROOT)" heartbeat --agent "$(AGENT)"

clean: ## Remove venv + cache + artifacts
	rm -rf $(VENV) __pycache__ .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
