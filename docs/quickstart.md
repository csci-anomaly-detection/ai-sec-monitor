## Quickstart

1) Install Docker Desktop (WSL2).
2) cd infra && docker compose up -d --build
3) Visit Grafana (http://localhost:3000), add Loki (http://loki:3100).
4) Generate events: see scripts/make-demo.ps1
