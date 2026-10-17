#!/usr/bin/env bash
set -euo pipefail

TTL_OVERRIDE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -ttl|--ttl) TTL_OVERRIDE="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done

PARENT_ID=$(docker compose exec -T spire-server \
  /opt/spire/bin/spire-server agent list \
  | awk '/SPIFFE ID/ {print $4; exit}')
[[ -z "$PARENT_ID" ]] && { echo "no attested agent"; exit 1; }

# manager (x509 ttl=60s, override with -ttl N)
docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID "$PARENT_ID" \
  -spiffeID spiffe://acme.test/manager \
  -selector docker:label:role:manager \
  -x509SVIDTTL ${TTL_OVERRIDE:-60}

# worker (x509 ttl=60s, override with -ttl N)
docker compose exec -T spire-server /opt/spire/bin/spire-server entry create \
  -parentID "$PARENT_ID" \
  -spiffeID spiffe://acme.test/worker \
  -selector docker:label:role:worker \
  -x509SVIDTTL ${TTL_OVERRIDE:-60}
