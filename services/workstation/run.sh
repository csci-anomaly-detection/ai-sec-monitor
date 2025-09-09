#!/usr/bin/env bash
set -e
TARGET="http://web"
echo "[workstation] traffic loop..."
while true; do
  curl -s ${TARGET}/healthz | jq . >/dev/null || echo "[workstation] healthz failed"
  curl -s -X POST ${TARGET}/login -H "Content-Type: application/json" -d '{"user":"student"}' >/dev/null
  curl -s -X POST ${TARGET}/login -H "Content-Type: application/json" -d '{"user":"badguy1"}' >/dev/null
  curl -s -X POST ${TARGET}/login -H "Content-Type: application/json" -d '{"user":"badguy2"}' >/dev/null
  sleep 30
done
