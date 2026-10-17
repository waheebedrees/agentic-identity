# agentic-identity Makefile

SHELL        := /bin/bash
COMPOSE      := docker compose
SPIRE_SERVER := /opt/spire/bin/spire-server

# Load .env if present (exports all vars to recipes)
-include .env
export
export MSYS_NO_PATHCONV=1

# Docker volume holding the agent's SVID and bootstrap bundle
VOL_AGENT ?= $(AGENT_DATA_VOLUME)

# Generator and registration script paths
GEN_SCRIPT := scripts/gen.py
REG_SCRIPT := scripts/register-entries.sh

.PHONY: help gen build certs volume bundle up down nuke restart \
        logs status list entries fingerprint clean-certs run

# Show available targets with their descriptions
help:
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# Regenerate docker-compose.yml and register-entries.sh from agents.yaml
gen:
	python $(GEN_SCRIPT)

# Build per-agent images (manager, worker, ...)
build: gen
	$(COMPOSE) build

# Generate x509pop CA and agent certificate for node attestation
certs:
	@bash -c 'set -e; \
	  export MSYS_NO_PATHCONV=1; \
	  mkdir -p ./spire/x509pop; cd ./spire/x509pop; \
	  if [ ! -f ca.crt ]; then \
	    echo ">> generating CA"; \
	    openssl req -x509 -newkey rsa:2048 -nodes \
	      -keyout ca.key -out ca.crt -days 3650 \
	      -subj "/O=MyOrg/CN=SPIRE x509pop CA"; \
	  else echo "   CA exists, skipping"; fi; \
	  if [ ! -f agent.key ]; then \
	    echo ">> generating agent key + CSR"; \
	    openssl req -newkey rsa:2048 -nodes \
	      -keyout agent.key -out agent.csr \
	      -subj "/O=MyOrg/CN=spire-agent-host"; \
	  else echo "   agent key exists, skipping"; fi; \
	  if [ ! -f agent.crt ]; then \
	    printf "[v3_agent]\nbasicConstraints = CA:FALSE\nkeyUsage = critical, digitalSignature, keyEncipherment\nextendedKeyUsage = clientAuth\n" > agent_ext.cnf; \
	    echo ">> signing agent cert"; \
	    openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
	      -out agent.crt -days 1825 \
	      -extfile agent_ext.cnf -extensions v3_agent 2>/dev/null; \
	  else echo "   agent cert exists, skipping"; fi; \
	  echo ">> verifying"; \
	  openssl verify -CAfile ca.crt agent.crt; \
	  openssl x509 -in agent.crt -noout -text | grep -A1 "Key Usage"'

# Ensure the agent data volume exists
volume:
	@docker volume inspect $(VOL_AGENT) >/dev/null 2>&1 \
	  || docker volume create $(VOL_AGENT) >/dev/null
	@echo "   volume $(VOL_AGENT) ready"

# Fetch trust bundle from the server and copy it into the agent data volume
bundle: volume
	@$(COMPOSE) up -d spire-init spire-server >/dev/null
	@echo ">> waiting for spire-server health..."
	@ok=0; \
	for i in $$(seq 1 60); do \
	  if $(COMPOSE) logs spire-server 2>&1 | grep -q "Starting Server APIs"; then \
	    ok=1; break; \
	  fi; \
	  sleep 1; \
	done; \
	if [ "$$ok" -ne 1 ]; then \
	  echo "!! server never became ready"; \
	  $(COMPOSE) logs --tail=30 spire-server; \
	  exit 1; \
	fi; \
	echo "   ready"
	@rm -f ./spire/bootstrap.crt
	@mkdir -p ./spire
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) bundle show -format pem > ./spire/bootstrap.crt
	@if [ ! -s ./spire/bootstrap.crt ]; then \
	  echo "!! bootstrap.crt is empty"; \
	  exit 1; \
	fi
	@echo "   fetched $$(wc -c < ./spire/bootstrap.crt) bytes"
	@docker run --rm \
	  -v $(VOL_AGENT):/data \
	  -v "$$(pwd)/spire:/src:ro" \
	  alpine sh -c 'cp /src/bootstrap.crt /data/bootstrap.crt'
	@echo "   copied into $(VOL_AGENT)"

# Start SPIRE infra (init, server, agent) and wait for attestation
up: bundle
	$(COMPOSE) up -d spire-init spire-server spire-agent
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

# Stop all services, keep volumes
down:
	$(COMPOSE) down

# Stop all services and remove volumes — full reset
nuke:
	$(COMPOSE) down -v
	@docker volume rm $(VOL_AGENT) 2>/dev/null || true
	@echo ">> nuked"

# Restart the SPIRE agent
restart:
	$(COMPOSE) restart spire-agent

# Follow logs for spire-server and spire-agent
logs:
	$(COMPOSE) logs -f spire-server spire-agent

# Show running containers
status:
	$(COMPOSE) ps

# Print the agent's x509pop fingerprint
fingerprint:
	@$(COMPOSE) logs spire-agent 2>&1 | grep -o 'x509pop/[a-f0-9]*' | head -1 | cut -d/ -f2

# List attested agents
list:
	$(COMPOSE) exec spire-server $(SPIRE_SERVER) agent list

# Show all registration entries
entries:
	@$(COMPOSE) exec -T spire-server $(SPIRE_SERVER) entry show

# Remove generated x509pop CA and agent certs
clean-certs:
	rm -rf ./spire/x509pop
	@echo ">> removed ./spire/x509pop"

# Full workflow: clean slate, build images, start infra, register, run workloads
run: nuke build certs up
	./$(REG_SCRIPT)
	$(COMPOSE) up -d manager worker
	$(COMPOSE) logs -f manager worker