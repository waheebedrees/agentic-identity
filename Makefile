# ─────────────────────────────────────────────────────────────────
# SPIRE x509pop + workload identity
# ─────────────────────────────────────────────────────────────────

SHELL        := /bin/bash
COMPOSE      := docker compose
SPIRE_SERVER := /opt/spire/bin/spire-server
SPIRE_AGENT  := /opt/spire/bin/spire-agent

# ── Parameters (override on the CLI) ─────────────────────────────
SPIFFE_ID  ?= spiffe://acme.test/my-agent
SELECTOR   ?= unix:uid:0
SVID_DIR   ?= ./svid
SOCKET     ?= /tmp/spire-agent/public/api.sock
VOL_AGENT  ?= agentic-identity_spire-agent-data

.PHONY: help up down nuke restart logs status \
        certs bundle volume register unregister entries \
        fetch show fingerprint clean clean-certs

help: ## Show this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ── Lifecycle ────────────────────────────────────────────────────

up: bundle ## Start the stack and wait for attestation
	$(COMPOSE) up -d
	@echo ">> waiting for spire-agent to attest..."
	@for i in $$(seq 1 30); do \
	  if $(COMPOSE) logs spire-agent 2>&1 | grep -q "Starting Workload and SDS APIs"; then \
	    echo "   attested"; break; \
	  fi; \
	  if [ "$$i" -eq 30 ]; then \
	    echo "!! agent never attested"; \
	    $(COMPOSE) logs --tail=30 spire-agent; \
	    exit 1; \
	  fi; \
	  sleep 1; \
	done

down: ## Stop the stack, keep volumes
	$(COMPOSE) down

nuke: ## Stop the stack and delete all volumes
	$(COMPOSE) down -v
	@docker volume rm $(VOL_AGENT) 2>/dev/null || true
	rm -rf $(SVID_DIR)
	@echo ">> nuked"

restart: ## Restart the agent only
	$(COMPOSE) restart spire-agent

logs: ## Tail server and agent logs
	$(COMPOSE) logs -f spire-server spire-agent

status: ## Show container status
	$(COMPOSE) ps

# ── Volume prep ──────────────────────────────────────────────────

volume: ## Ensure the agent data volume exists
	@docker volume inspect $(VOL_AGENT) >/dev/null 2>&1 \
	  || docker volume create $(VOL_AGENT) >/dev/null
	@echo "   volume $(VOL_AGENT) ready"

# ── Certificates ─────────────────────────────────────────────────

certs: ## Generate CA + agent cert/key into ./spire/x509pop
	@bash -c 'set -e; \
	  export MSYS_NO_PATHCONV=1; \
	  mkdir -p ./spire/x509pop; cd ./spire/x509pop; \
	  if [ ! -f ca.crt ]; then \
	    echo ">> generating CA"; \
	    openssl req -x509 -newkey rsa:2048 -nodes \
	      -keyout ca.key -out ca.crt -days 3650 \
	      -subj "//O=MyOrg/CN=SPIRE x509pop CA"; \
	  else echo "   CA exists, skipping"; fi; \
	  if [ ! -f agent.key ]; then \
	    echo ">> generating agent key + CSR"; \
	    openssl req -newkey rsa:2048 -nodes \
	      -keyout agent.key -out agent.csr \
	      -subj "//O=MyOrg/CN=spire-agent-host"; \
	  else echo "   agent key exists, skipping"; fi; \
	  printf "[v3_agent]\nbasicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = clientAuth\n" > agent_ext.cnf; \
	  echo ">> signing agent cert"; \
	  openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	    -out agent.crt -days 1825 \
	    -extfile agent_ext.cnf -extensions v3_agent 2>/dev/null; \
	  echo ">> verifying"; \
	  openssl verify -CAfile ca.crt agent.crt; \
	  openssl x509 -in agent.crt -noout -text | grep -A1 "Key Usage"'
	
# ── Trust bundle ─────────────────────────────────────────────────

bundle: volume ## Fetch the server trust bundle into the agent volume
	@$(COMPOSE) up -d spire-init spire-server >/dev/null
	@echo ">> waiting for spire-server health..."
	@ok=0; \
	for i in $$(seq 1 30); do \
	  if $(COMPOSE) exec -T spire-server $(SPIRE_SERVER) healthcheck >/dev/null 2>&1; then \
	    ok=1; break; \
	  fi; \
	  sleep 1; \
	done; \
	if [ "$$ok" -ne 1 ]; then \
	  echo "!! server never became healthy"; \
	  $(COMPOSE) logs --tail=30 spire-server; \
	  exit 1; \
	fi; \
	echo "   healthy"
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) bundle show -format pem \
	  | docker run --rm -i -v $(VOL_AGENT):/data \
	      alpine sh -c 'cat > /data/bootstrap.crt'
	@echo "   wrote bootstrap.crt into $(VOL_AGENT)"

# ── Workload registration ────────────────────────────────────────

fingerprint: ## Print the agent's current x509pop fingerprint
	@$(COMPOSE) logs spire-agent 2>&1 | grep -o 'x509pop/[a-f0-9]*' | head -1 | cut -d/ -f2

register: ## Register the workload (SPIFFE_ID=... SELECTOR=...)
	@FP=$$($(COMPOSE) logs spire-agent 2>&1 | grep -o 'x509pop/[a-f0-9]*' | head -1 | cut -d/ -f2); \
	if [ -z "$$FP" ]; then \
	  echo "!! agent has no fingerprint — run 'make up' first"; \
	  exit 1; \
	fi; \
	$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry create \
	  -spiffeID  $(SPIFFE_ID) \
	  -parentID  spiffe://acme.test/spire/agent/x509pop/$$FP \
	  -selector  $(SELECTOR); \
	echo ">> registered $(SPIFFE_ID) with selector $(SELECTOR)"

unregister: ## Delete the workload entry by SPIFFE_ID
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry delete \
	  -spiffeID $(SPIFFE_ID)
	@echo ">> deleted $(SPIFFE_ID)"

entries: ## List registered entries
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry show

# ── SVID fetch ───────────────────────────────────────────────────

fetch: ## Fetch an X.509 SVID into $(SVID_DIR)
	@mkdir -p $(SVID_DIR)
	@$(COMPOSE) exec spire-agent $(SPIRE_AGENT) api fetch x509 \
	  -socketPath $(SOCKET) \
	  -write /svid
	@echo ">> SVID written to $(SVID_DIR)"

show: ## Print the SPIFFE ID from the fetched SVID
	@openssl x509 -in $(SVID_DIR)/svid.0.pem -noout -text | grep -A1 "Subject Alternative Name"

# ── Cleanup ──────────────────────────────────────────────────────

clean: ## Remove generated SVIDs
	rm -rf $(SVID_DIR)
	@echo ">> cleaned $(SVID_DIR)"

clean-certs: ## Remove all generated certificates
	rm -rf ./spire/x509pop
	@echo ">> removed ./spire/x509pop"