
# agentic-identity Makefile

SHELL        := /bin/bash
COMPOSE      := docker compose
SPIRE_SERVER := /opt/spire/bin/spire-server
SPIRE_AGENT  := /opt/spire/bin/spire-agent

# Load .env if present
-include .env
export

# Host paths (used by Make and by Compose as bind-mount sources)
SVID_HOST_DIR ?= $(SVID_HOST_DIR)
VOL_AGENT ?= $(AGENT_DATA_VOLUME)

# Parameters with defaults (override with .env or CLI)
SOCKET ?= $(SPIRE_SOCKET_PATH)

SPIFFE_ID  ?= $(SPIFFE_ID)
SELECTOR   ?= $(SELECTOR)

.PHONY: help up down nuke restart logs status \
        certs bundle volume register unregister entries \
        fetch show fingerprint clean clean-certs

help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: bundle
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

down:
	$(COMPOSE) down

nuke:
	$(COMPOSE) down -v
	@docker volume rm $(VOL_AGENT) 2>/dev/null || true
	rm -rf $(SVID_HOST_DIR)
	@echo ">> nuked"

restart:
	$(COMPOSE) restart spire-agent

logs:
	$(COMPOSE) logs -f spire-server spire-agent

status:
	$(COMPOSE) ps

volume:
	@docker volume inspect $(VOL_AGENT) >/dev/null 2>&1 \
	  || docker volume create $(VOL_AGENT) >/dev/null
	@echo "   volume $(VOL_AGENT) ready"

certs:
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

bundle: volume
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

fingerprint:
	@$(COMPOSE) logs spire-agent 2>&1 | grep -o 'x509pop/[a-f0-9]*' | head -1 | cut -d/ -f2

register:
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

unregister:
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry delete \
	  -spiffeID $(SPIFFE_ID)
	@echo ">> deleted $(SPIFFE_ID)"

entries:
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry show

fetch:
	@mkdir -p $(SVID_HOST_DIR)
	@$(COMPOSE) exec spire-agent $(SPIRE_AGENT) api fetch x509 \
	  -socketPath $(SOCKET) \
	  -write /svid
	@echo ">> SVID written to $(SVID_HOST_DIR)"

show:
	@openssl x509 -in $(SVID_HOST_DIR)/svid.0.pem -noout -text \
	  | grep -A1 "Subject Alternative Name"

clean:
	rm -rf $(SVID_HOST_DIR)
	@echo ">> cleaned $(SVID_HOST_DIR)"

clean-certs:
	rm -rf ./spire/x509pop
	@echo ">> removed ./spire/x509pop"