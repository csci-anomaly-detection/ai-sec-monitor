# Docker Compose Quick Reference

## Starting the Pipeline

### Full System Start
```bash
# Start all services (builds if needed)
docker compose up --build

# Start in detached mode (background)
docker compose up -d --build

# Start specific service
docker compose up agent
```

### Individual Service Management
```bash
# Start ChromaDB only
docker compose up chroma -d

# Start PostgreSQL only
docker compose up postgres -d

# Start Ollama only
docker compose up ollama -d

# Start agent (depends on chroma, postgres, ollama)
docker compose up agent
```

## Monitoring & Logs

### View Logs
```bash
# All services
docker compose logs

# Follow logs in real-time
docker compose logs -f

# Specific service
docker compose logs agent
docker compose logs ollama
docker compose logs chroma
docker compose logs postgres

# Last 100 lines
docker compose logs --tail=100 agent

# Since timestamp
docker compose logs --since="2023-11-12T10:00:00"
```

### Check Status
```bash
# List running services
docker compose ps

# Check resource usage
docker stats
```

## Stopping & Cleanup

### Stop Services
```bash
# Stop all services (preserves data)
docker compose stop

# Stop specific service
docker compose stop agent

# Stop and remove containers
docker compose down

# Stop and remove containers + volumes (DELETES DATA)
docker compose down -v

# Stop and remove containers + images
docker compose down --rmi all
```

### Restart Services
```bash
# Restart all services
docker compose restart

# Restart specific service
docker compose restart agent
docker compose restart ollama
```

## Rebuilding & Updates

### Rebuild After Code Changes
```bash
# Rebuild agent container (after changing Python code)
docker compose build agent
docker compose up agent

# Force rebuild (no cache)
docker compose build --no-cache agent
```

### Pull Latest Images
```bash
# Pull latest images for all services
docker compose pull

# Pull specific image
docker compose pull ollama
docker compose pull chroma
```

## Debugging & Troubleshooting

### Execute Commands in Containers
```bash
# Open bash shell in agent container
docker compose exec agent bash

# Run Python command
docker compose exec agent python -c "print('Hello')"

# Check Python imports
docker compose exec agent python -c "from validation.validation_orchestrator import ValidationOrchestrator"

# List files
docker compose exec agent ls -la /app

# View environment variables
docker compose exec agent env
```

### Access Databases
```bash
# PostgreSQL
docker compose exec postgres psql -U myuser -d alertsdb

# List tables
docker compose exec postgres psql -U myuser -d alertsdb -c "\dt"

# Query data
docker compose exec postgres psql -U myuser -d alertsdb -c "SELECT * FROM alert_batches LIMIT 5;"
```

### Test Services
```bash
# Test Ollama
curl http://localhost:1561/api/generate -d '{"model":"llama3.1:8b","prompt":"test"}'

# Test ChromaDB
curl http://localhost:1563/api/v1/heartbeat

# Test PostgreSQL
docker compose exec postgres pg_isready -U myuser
```

### View Container Details
```bash
# Inspect container
docker inspect ai_analysis

# View container logs location
docker inspect ai_analysis | jq '.[0].LogPath'

# View mounts
docker inspect ai_analysis | jq '.[0].Mounts'
```

## Volume Management

### List Volumes
```bash
# List all volumes
docker volume ls

# Inspect specific volume
docker volume inspect gen-ai-agents_chroma-data
```

### Clean Up Volumes
```bash
# Remove all stopped containers and unused volumes
docker system prune -a --volumes

# Remove specific volume (stops containers first)
docker compose down
docker volume rm gen-ai-agents_chroma-data
docker volume rm gen-ai-agents_pgdata
docker volume rm gen-ai-agents_ollama-data
```

### Backup Volumes
```bash
# Backup ChromaDB data
docker compose cp chroma:/chroma ./backup/chroma-data

# Backup PostgreSQL data
docker compose exec postgres pg_dump -U myuser alertsdb > backup/alertsdb_backup.sql
```

## Environment & Configuration

### Override Environment Variables
```bash
# Set environment variable for single run
ENABLE_VALIDATION=false docker compose up agent

# Multiple variables
ENABLE_VALIDATION=false LOG_LOCATION=/app/logs/custom.json docker compose up agent
```

### Use Different Compose File
```bash
# Use custom compose file
docker compose -f docker.compose.prod.yml up

# Use multiple compose files (override)
docker compose -f docker.compose.yml -f docker.compose.override.yml up
```

## Pipeline-Specific Commands

### Run Pipeline Stages Individually

```bash
# Run validation only
docker compose exec agent python -c "
from validation.validation_orchestrator import ValidationOrchestrator
validator = ValidationOrchestrator()
validated, stats = validator.validate_eve_json('/app/logs/eve.json')
print(stats)
"

# Run ChromaDB setup only
docker compose exec agent python /app/chroma_setup.py

# Run PostgreSQL setup only
docker compose exec agent python /app/postgres_setup.py

# Run full pipeline
docker compose exec agent python /app/main.py
```

### View Outputs
```bash
# View final report
docker compose exec agent cat /app/output/final_report.json

# View validated logs
docker compose exec agent cat /app/logs/eve_validated.json

# Copy output to host
docker compose cp agent:/app/output/final_report.json ./
```

### Tail Pipeline Logs During Run
```bash
# Follow agent logs and filter
docker compose logs -f agent | grep "STAGE"
docker compose logs -f agent | grep "✅"
docker compose logs -f agent | grep "ERROR"
```

## Performance & Resource Management

### Limit Resources
```bash
# Limit CPU (2 cores)
docker compose up --scale agent=1 --cpus=2 agent

# Limit memory (4GB)
docker compose up --scale agent=1 --memory=4g agent
```

### Check Resource Usage
```bash
# Real-time stats
docker stats

# Memory usage
docker stats --format "table {{.Name}}\t{{.MemUsage}}"

# CPU usage
docker stats --format "table {{.Name}}\t{{.CPUPerc}}"
```

## GPU Management (Ollama)

### Check GPU
```bash
# Verify GPU in Ollama container
docker compose exec ollama nvidia-smi

# Check CUDA version
docker compose exec ollama nvcc --version
```

### GPU Troubleshooting
```bash
# If GPU not working, verify docker has GPU support
docker run --rm --gpus all nvidia/cuda:11.8.0-base-ubuntu22.04 nvidia-smi

# Check docker compose GPU config
docker compose config | grep -A 5 "ollama"
```

## Common Workflows

### Fresh Start (Clean Slate)
```bash
# Stop everything and remove all data
docker compose down -v
rm -rf chroma-data pgdata ollama-data output

# Start fresh
docker compose up --build
```

### Update Code & Restart
```bash
# After changing Python code in agents/ or python-files/
docker compose restart agent

# Or rebuild if dependencies changed
docker compose build agent
docker compose up agent
```

### Debug Failed Pipeline
```bash
# Check what failed
docker compose logs agent | tail -50

# Enter container to investigate
docker compose exec agent bash

# Check files
ls -la /app/logs/
ls -la /app/output/

# Test imports
python -c "import sys; print(sys.path)"
```

### Production Deployment
```bash
# Use production compose file
docker compose -f docker.compose.prod.yml up -d

# Check health
docker compose ps
docker compose logs --tail=50

# Monitor
watch docker compose ps
```

## Useful Aliases

Add to your `.bashrc` or `.zshrc`:

```bash
alias dcu='docker compose up'
alias dcd='docker compose down'
alias dcl='docker compose logs -f'
alias dcr='docker compose restart'
alias dce='docker compose exec'
alias dcps='docker compose ps'

# Pipeline-specific
alias pipeline-start='docker compose up --build'
alias pipeline-logs='docker compose logs -f agent'
alias pipeline-stop='docker compose down'
alias pipeline-restart='docker compose restart agent'
alias pipeline-shell='docker compose exec agent bash'
alias pipeline-output='docker compose exec agent cat /app/output/final_report.json | jq .'
```

## Emergency Commands

### Kill Everything
```bash
# Nuclear option - stops all Docker containers
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)

# Remove all volumes
docker volume prune -f

# Remove all images
docker image prune -a -f
```

### Reset Docker
```bash
# Restart Docker daemon (macOS)
killall Docker && open /Applications/Docker.app

# Restart Docker daemon (Linux)
sudo systemctl restart docker
```

---

For more Docker Compose commands: https://docs.docker.com/compose/reference/
