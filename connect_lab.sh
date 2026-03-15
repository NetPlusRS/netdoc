#!/bin/bash
# Podlacza workery NetDoc do sieci laboratoryjnej (netdoc_lab)
# Uruchom PO: docker compose -f docker-compose.lab.yml up -d

NET="netdoc_lab"
WORKERS="netdoc-snmp netdoc-cred netdoc-vuln netdoc-ping netdoc-web"

echo "Podlaczanie workerow NetDoc do sieci $NET..."
for W in $WORKERS; do
  if docker inspect "$W" &>/dev/null; then
    docker network connect "$NET" "$W" 2>/dev/null && echo "  OK: $W" || echo "  -- $W (juz podlaczony?)"
  else
    echo "  SKIP: $W (kontener nie istnieje)"
  fi
done
echo ""
echo "Pamietaj: dodaj 172.28.0.0/24 do NETWORK_RANGES w .env i zrestartuj skan"
echo "  Urzadzenia lab: 172.28.0.10-12 (Conpot), 172.28.0.20 (router), 172.28.0.30 (SSH), 172.28.0.40 (HMI)"
