# SOC Compass Skill

An [Agent Skill](https://agentskills.io) that enables AI agents (Claude Code, Cursor, Copilot, Codex, etc.) to conduct security investigations on the [SOC Compass](https://soccompass.com) platform.

## Installation

```bash
npx skills add Hero988/soc-compass-skill
```

## What it does

The AI agent acts as a SOC analyst:

1. Reads workspace context and SIEM configuration
2. Formulates investigation queries (SPL, KQL, ESQL)
3. Asks you to run queries in your SIEM and paste results
4. Analyzes results and asks follow-up questions
5. Writes a verdict and investigation report
6. Saves investigation context for future reference

## Requirements

- A SOC Compass account with an API key (`soc_sk_...`)
- Access to your SIEM (Splunk, Elastic, or Microsoft Sentinel)

## Getting an API key

1. Log in to SOC Compass
2. Go to **Profile > API Keys**
3. Click **Create API Key**
4. Copy the key (shown only once)

## Usage

Once installed, the skill auto-triggers when you mention SOC Compass, security investigations, or alert triage. You can also invoke it directly:

```
/soc-compass
```

Example: "Investigate alert ALERT-2024-001 in workspace k7dj9x2m3abc"

## Supported modes

- **Alert Triage** — Dual-hypothesis analysis with classification framework
- **SOC Investigation** — Broader evidence-first investigation
- **VM Forensics** — OSCAR-DFIR framework for disk/memory analysis
- **Sigma Rules** — Detection rule engineering

## Skill structure

```
soc-compass/
  SKILL.md                          # Core skill instructions
  assets/openapi.json               # API specification
  references/
    alert-triage-methodology.md     # Classification framework
    vm-forensics-methodology.md     # OSCAR-DFIR guide
    sigma-rule-methodology.md       # Sigma YAML reference
    siem-query-guides.md            # SPL/KQL/ESQL examples
    report-format.md                # 9-section report template
    investigation-principles.md     # Core principles
```

## Compatible with

Works with 30+ AI tools including Claude Code, Cursor, GitHub Copilot, VS Code, OpenAI Codex, Gemini CLI, Windsurf, and more.
