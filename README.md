# SOC Compass Skill

An [Agent Skill](https://agentskills.io) that enables AI agents to conduct security investigations on the [SOC Compass](https://soccompass.com) platform. The agent acts as the SOC analyst — reading workspace context, formulating SIEM queries, analyzing results, and writing verdicts.

## Installation

### Claude Code

**Git Bash / macOS / Linux:**

```bash
mkdir -p ~/.claude/skills/soc-compass && curl -sL "https://raw.githubusercontent.com/Hero988/soc-compass-skill/master/soc-compass/SKILL.md?t=$(date +%s)" -o ~/.claude/skills/soc-compass/SKILL.md
```

**PowerShell (Windows):**

```powershell
New-Item -ItemType Directory -Force -Path "$HOME/.claude/skills/soc-compass" | Out-Null; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Hero988/soc-compass-skill/master/soc-compass/SKILL.md?t=$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" -OutFile "$HOME/.claude/skills/soc-compass/SKILL.md"
```

The skill auto-loads in every Claude Code session. Verify with: "What skills are available?"

### Other agents (Cursor, Codex, Gemini CLI, Copilot, etc.)

```bash
npx skills add Hero988/soc-compass-skill
```

Installs via [skills.sh](https://skills.sh) — works with 30+ AI tools.

## Setup

1. Create an account at [soccompass.com](https://soccompass.com)
2. Go to **Profile > API Keys**
3. Click **Create API Key** and copy the key (shown only once)
4. Provide the key to your AI agent when it asks (format: `soc_sk_...`)

## Usage

The skill auto-triggers when you mention SOC Compass, security investigations, alert triage, or SIEM queries. Provide your API key inline when prompted.

**Example prompts:**

- "Investigate this alert in workspace `k7dj9x2m3abc`: [paste alert details]"
- "Continue the investigation on conversation `j5n8x2p4q7abc`"
- "What is the verdict for the phishing alert we investigated?"

## What it does

1. Reads workspace context and SIEM configuration (Splunk / Elastic / Sentinel)
2. Asks for SIEM schema if not cached, then formulates investigation queries
3. Asks you to run queries in your SIEM and paste results
4. Analyzes results, checks IOCs, maps to MITRE ATT&CK
5. Writes a verdict and 9-section investigation report
6. Saves investigation context for seamless resume

## Supported modes

- **Alert Triage** — Dual-hypothesis analysis with classification framework
- **SOC Investigation** — Broader evidence-first investigation
- **VM Forensics** — OSCAR-DFIR framework for disk/memory analysis
- **Sigma Rules** — Detection rule engineering

## API

- **Base URL:** `https://astute-cormorant-480.convex.site/api/v1`
- **Auth:** `Authorization: Bearer soc_sk_<key>`
- **Docs:** [API Reference](https://soccompass.com/docs/api)

## License

MIT
