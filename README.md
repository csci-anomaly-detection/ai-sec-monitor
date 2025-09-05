# AI-Sec-Monitor

AI-Sec-Monitor is a class project for building an **AI-augmented security monitoring system** in a simulated campus environment.  
The goal is to collect logs, detect suspicious activity, and use AI to summarize alerts and send notifications.  

This repository is structured for teamwork. It uses **branch protection rules** to keep `main` stable, and all changes must go through pull requests.

---

## Project Goals
- Simulate a small campus-like environment with web servers, databases, and sensors.
- Collect logs and network data into a central system.
- Detect key events like failed logins, port scans, and honeypot activity.
- Use AI to triage alerts and recommend next steps.
- Send alerts via dashboards and notifications.

---
## Repository Structure
```
ai-sec-monitor/
├─ docs/ # Documentation
├─ infra/ # Docker and infrastructure
├─ sim/ # Simulated servers & attack scenarios
├─ ingest/ # Log collection and schema mapping
├─ detect/ # Detection rules and engine
├─ ai/ # AI triage service
├─ notify/ # Alerting integrations
├─ ui/ # Dashboards and optional UI
└─ scripts/ # Helper scripts
```
---

## Workflow for Classmates

### Branch Rules
- **`main` is protected.**
  - You cannot push directly to `main`.
  - All changes must go through a pull request (PR).
  - At least one review is required before merging.
- This keeps the project stable and avoids breaking the main line.

ChatGPT said:

Ah, I see what happened — when you pasted commands into the README, GitHub didn’t recognize them as code blocks. Same fix as before: wrap them with triple backticks.

Here’s the cleaned-up version of that whole section with proper Markdown formatting:

## How to Contribute

### Stay up to date
```bash
git checkout main
git pull

Create a new branch
git checkout -b feat/<short-description>


Examples:

git checkout -b feat/docker-compose
git checkout -b fix/readme-typos

Do your edits, then commit
git add .
git commit -m "feat: add docker-compose stack"

Push your branch to GitHub
git push -u origin feat/<short-description>

Open a Pull Request (PR) on GitHub

Select main as the base branch.

Assign a classmate to review.

After approval, merge through the GitHub UI.

Branch Naming Convention

feat/... → new features (e.g., feat/web-app)

fix/... → bug fixes (e.g., fix/login-error)

chore/... → cleanup or maintenance (e.g., chore/update-readme)

Quickstart (infrastructure only for now)

Install Docker Desktop (Windows with WSL2 backend).

Clone the repository:

git clone https://github.com/<your-username>/ai-sec-monitor.git
cd ai-sec-monitor/infra


Launch the environment:

docker compose up -d --build


Access services (once configured):

OpenSearch Dashboards: http://localhost:5601

Grafana: http://localhost:3000

Demo web app: http://localhost:8080

License

Apache 2.0 — see LICENSE
.

Notes

This project uses only synthetic data in a controlled lab environment.

Do not connect it to real institutional systems without explicit written permission.
