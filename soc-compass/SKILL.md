---
name: soc-compass
description: Conducts security investigations on SOC Compass. The AI agent reads workspace context, asks the user to run SIEM queries, analyzes results, and writes verdicts. Use when the user mentions SOC Compass, security investigations, alert triage, SIEM queries, threat analysis, Splunk, Elastic, Sentinel, IOC lookups, or investigation workspaces. Do not use for general cybersecurity questions not involving the SOC Compass platform.
---

# SOC Compass API

Provides programmatic access to SOC Compass — a security investigation platform. The agent acts as the SOC analyst: reading workspace context, formulating SIEM queries, asking the user to execute them, analyzing results, and writing verdicts.

## How to call the API

**ALWAYS use `curl` via the Bash tool.** Do not use WebFetch, fetch(), or any other HTTP client.

```bash
API="https://astute-cormorant-480.convex.site/api/v1"
KEY="<user-provided-api-key>"

curl -s "$API/ENDPOINT" -H "Authorization: Bearer $KEY"
```

The user provides their API key (format: `soc_sk_<32hex>`) when invoking this skill.

## Automated scenarios

The skill handles these scenarios automatically based on what the user provides:

### Scenario A: New investigation

User gives alert + workspace ID. Follow these steps in order:

1. **Get workspace context**
```bash
curl -s "$API/workspaces/{workspaceId}" -H "Authorization: Bearer $KEY"
```
Note the `siemProvider` (splunk/elastic/sentinel), `mode`, `contextInput`, and `dataSource`.

2. **Create conversation**
```bash
curl -s -X POST "$API/workspaces/{workspaceId}/conversations" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"title": "Investigation: {alertTitle}", "eventId": "{alertId}"}'
```
Save the returned `id` as `CONV_ID`.

3. **Check for cached context**
```bash
curl -s "$API/conversations/{CONV_ID}/context" -H "Authorization: Bearer $KEY"
```
If `agentContext` is null, this is a fresh investigation. If it has data, you're resuming.

4. **Schema discovery** (if no cached schema in context)

Ask the user directly based on the SIEM provider:

- **Splunk**: "Please run this query in Splunk and paste the results: `index=* NOT index=_* earliest=-30d | head 10000 | fieldsummary maxvals=10 | sort -count | head 60`"
- **Elastic**: "Please paste 5-10 sample events from Kibana Discover for the relevant index."
- **Sentinel**: "Please paste 3-5 sample events from Azure Monitor Logs for the relevant table."

After the user provides results, save them in context:
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"schema": {PARSED_SCHEMA}, "provider": "{siemProvider}", "investigationPhase": "initial"}'
```

5. **Investigation loop**

Formulate SIEM queries based on the alert, schema, and investigation methodology (see `references/alert-triage-methodology.md`). Ask the user to run each query:

"Please run this {SPL/KQL/ESQL} query and paste the results:
```
{query}
```
**Purpose:** {why this query matters}"

Analyze results after each query. Ask follow-up queries as needed. Apply the classification framework after 1-3 initial queries.

6. **Write verdict**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/verdict" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "eventId": "{alertId}",
    "verdict": "True Positive",
    "confidence": 92,
    "severity": "high",
    "escalationRequired": true,
    "classificationRationale": "Multiple indicators confirm..."
  }'
```

Valid verdicts: `True Positive`, `False Positive`, `Suspicious`, `Requires Further Investigation`, `Unknown`

7. **Post report**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/messages" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"role": "assistant", "content": "{FULL_9_SECTION_REPORT}"}'
```

Use the 9-section report format from `references/report-format.md`.

8. **Save context**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "schema": {...},
    "queriesRun": [{"query": "...", "purpose": "...", "resultSummary": "..."}],
    "iocs": [{"value": "...", "type": "ip", "verdict": "malicious"}],
    "mitreTechniques": [{"id": "T1566.001", "name": "...", "evidence": "..."}],
    "keyFindings": ["..."],
    "verdict": {"verdict": "...", "confidence": 92},
    "investigationPhase": "completed"
  }'
```

### Scenario B: Resume investigation

User references a conversation ID:
```bash
curl -s "$API/conversations/{CONV_ID}/context" -H "Authorization: Bearer $KEY"
```
Read the saved context and resume from where you left off. No need to re-read messages.

### Scenario C: General question

User asks a question (not a full investigation):
1. Read workspace context for relevant info
2. Answer directly
3. Save Q&A in conversation context

### Scenario D: Extra context

User provides info beyond what's in the workspace. Save it alongside investigation state in context.

## Asking the user for information

Ask the user DIRECTLY in the conversation. No API endpoint needed:

- "Please run this query in your {Splunk/Elastic/Sentinel}: `{query}`"
- "Please check this IOC in VirusTotal/ThreatFox: `{ioc}`"
- "Is this server authorized to make outbound connections to external IPs?"

Guidelines:
- Ask ONE query at a time (user runs manually)
- Always explain the PURPOSE of each query
- If user provides partial results, ask for clarification
- If user can't run a query, adapt your approach
- Save context after each major step (enables resume)

## Investigation modes

Auto-detected from the workspace `mode` field:

**Alert Triage** (`ultimate_trigger`, default):
Dual-hypothesis analysis — evaluate both benign and malicious explanations. See `references/alert-triage-methodology.md`. Apply classification framework after 1-3 queries.

**SOC Investigation** (`soc_investigation_trigger`):
Broader scope, SIEM optional, evidence-first approach. More flexible than triage.

**VM Forensics** (`vm_forensics_trigger`):
OSCAR-DFIR framework. Ask user to run ONE command at a time on the VM. See `references/vm-forensics-methodology.md`.

**Sigma Rules** (`sigma_rule_trigger`):
Detection rule engineering. Ask for log samples, write Sigma rules. No SIEM queries needed. See `references/sigma-rule-methodology.md`.

If the question doesn't match any mode, answer directly using workspace context.

## SIEM query quick reference

**Splunk SPL:**
- Always use relative time: `earliest=-60m` or `earliest=-24h`
- End queries with `| head 20`
- Default: `index=main sourcetype=_json` (adjust per schema)
- NEVER use absolute timestamps

**Elastic ESQL:**
- Start with `FROM <index-pattern>`
- Use `==` for equality (double equals)
- Quote keyword values: `"4624"` not `4624`
- Time: `WHERE timestamp >= NOW() - 1 hour`
- End with `| LIMIT 20`

**Sentinel KQL:**
- Start with table name: `SecurityEvent`, `SigninLogs`, etc.
- Use `==` for equality, `has` for word match, `contains` for substring
- Time: `| where TimeGenerated > ago(24h)`
- End with `| take 20`

Full guide: `references/siem-query-guides.md`

## Endpoint reference

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Health check (no auth) |
| `GET` | `/me` | User info |
| `GET` | `/me/credits` | Credit balance |
| `GET` | `/workspaces` | List workspaces |
| `GET` | `/workspaces/:id` | Workspace details + context |
| `POST` | `/workspaces` | Create workspace |
| `PATCH` | `/workspaces/:id` | Update workspace |
| `DELETE` | `/workspaces/:id` | Archive workspace |
| `GET` | `/workspaces/:wsId/conversations` | List conversations |
| `POST` | `/workspaces/:wsId/conversations` | Create conversation |
| `GET` | `/conversations/:id` | Conversation details |
| `GET` | `/conversations/:id/messages` | Message history |
| `POST` | `/conversations/:id/messages` | Post message (user/assistant) |
| `GET` | `/conversations/:id/context` | Get agent context |
| `POST` | `/conversations/:id/context` | Save agent context |
| `PATCH` | `/conversations/:id/context` | Merge-update context |
| `GET` | `/conversations/:id/verdict` | Read verdicts |
| `POST` | `/conversations/:id/verdict` | Write verdict |
| `GET` | `/conversations/:id/status` | Processing status |

All endpoints require `Authorization: Bearer soc_sk_<key>` except `/health`.

## Error codes

```json
{ "error": { "code": "...", "message": "...", "status": 400 } }
```

| Code | Status | Meaning |
|------|--------|---------|
| `bad_request` | 400 | Invalid input |
| `unauthorized` | 401 | Invalid/expired API key |
| `not_found` | 404 | Resource not found |
| `rate_limited` | 429 | Too many requests (60/min standard) |
| `internal_error` | 500 | Server error |

## Critical rules

1. **Context is AUTHORITATIVE** — never contradict user-provided workspace context without concrete evidence
2. **Temporal investigation is MANDATORY** — always check what happened AFTER the alert event
3. **Classify EARLY** — after 1-3 initial queries, apply the classification framework
4. **Save context after each major step** — this enables resuming if the session is interrupted
5. **Post the final report as an assistant message** so it appears in the frontend conversation
6. **Use the correct SIEM query syntax** for the workspace's provider (SPL/KQL/ESQL)
7. **Never fabricate query results** — only use data the user has provided
8. **Follow the 9-section report format** from `references/report-format.md`
9. **IOCs must be individually verified** — don't assume an IOC is malicious without evidence
10. **TP does not equal confirmed malware** — True Positive means the alert correctly identified suspicious activity requiring response
