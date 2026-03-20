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

## CRITICAL: Schema discovery is MANDATORY

**You MUST discover the SIEM schema BEFORE writing ANY investigation query.** Do NOT guess index names, sourcetypes, or field names. Every SIEM instance has different indexes, sourcetypes, and field names. If you skip this step, your queries WILL fail.

The schema tells you:
- What **indexes** exist (e.g., `corp`, `main`, `wineventlog`)
- What **sourcetypes** exist (e.g., `WinEventLog`, `WinEventLog:Security`, `xmlwineventlog`)
- What **fields** are available and their exact names (e.g., `EventCode` vs `event.code` vs `EventID`)
- How many events each field/index contains

**Without the schema, you are blind. ALWAYS get the schema first.**

## Automated scenarios

### Scenario A: New investigation

User gives alert + workspace ID. Follow these steps **in exact order**:

**Step 1: Get workspace context**
```bash
curl -s "$API/workspaces/{workspaceId}" -H "Authorization: Bearer $KEY"
```
Note the `siemProvider` (splunk/elastic/sentinel), `mode`, `contextInput`, and `dataSource`.

**Step 2: Create conversation**
```bash
curl -s -X POST "$API/workspaces/{workspaceId}/conversations" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"title": "Investigation: {alertTitle}", "eventId": "{alertId}"}'
```
Save the returned `id` as `CONV_ID`.

**Step 3: Check for cached context**
```bash
curl -s "$API/conversations/{CONV_ID}/context" -H "Authorization: Bearer $KEY"
```
If `agentContext` has a `schema` field → you already have the schema, skip to Step 5.
If `agentContext` is null → this is a fresh investigation, proceed to Step 4.

**Step 4: MANDATORY schema discovery**

This step is NON-NEGOTIABLE. You MUST do this before ANY investigation query.

Ask the user directly based on the SIEM provider from Step 1:

**Splunk:**
> Please run this query in Splunk and paste the **full results**:
> ```
> index=* NOT index=_* earliest=-30d | head 10000 | fieldsummary maxvals=10 | sort -count | head 60
> ```
> This will show me what indexes, sourcetypes, and fields exist in your environment so I can write accurate queries.

**Elastic:**
> Please go to Kibana Discover, select the relevant index pattern, and paste **5-10 sample events** as JSON. I need to see the actual field names and structure to write correct ES|QL queries.

**Sentinel:**
> Please run this in Azure Monitor Logs and paste the results:
> ```
> search * | summarize count() by $table | sort by count_ desc | take 20
> ```
> Then paste **3-5 sample events** from the most relevant table. I need to see the actual field names.

After the user provides the schema results:

1. **Parse the schema carefully** — extract index names, sourcetypes, field names, and event counts
2. **Save it immediately to context** so you never need to ask again:
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "schema": {
      "provider": "splunk",
      "indexes": ["corp", "main"],
      "sourcetypes": ["WinEventLog", "WinEventLog:Security"],
      "fields": ["EventCode", "ComputerName", "Account_Name", "..."],
      "rawSchemaOutput": "...the full output from the user..."
    },
    "investigationPhase": "schema_complete"
  }'
```

3. **ALL subsequent queries MUST use field names, index names, and sourcetypes from the schema.** Never guess or use defaults.

**Step 5: Investigation loop**

NOW you can formulate queries — using ONLY the field names, indexes, and sourcetypes from the schema.

For each query:
1. Check the schema to confirm the fields you need exist
2. Use the correct index name from the schema (NOT `index=main` unless the schema shows `main`)
3. Use the correct sourcetype from the schema
4. Ask the user to run it and paste results:

> Please run this {SPL/KQL/ESQL} query and paste the results:
> ```
> {query using schema-verified field names}
> ```
> **Purpose:** {why this query matters for the investigation}

Analyze results after each query. Apply the classification framework (see `references/alert-triage-methodology.md`) after 1-3 initial queries.

**Step 6: Write verdict**
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

**Step 7: Post report**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/messages" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"role": "assistant", "content": "{FULL_9_SECTION_REPORT}"}'
```

Use the 9-section report format from `references/report-format.md`.

**Step 8: Save full context**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{
    "schema": {"...saved from Step 4..."},
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
Read the saved context — it already has the schema, queries run, findings, etc. Resume from where you left off. No need to re-read messages or redo schema discovery.

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

## SIEM query rules (ONLY use after schema discovery)

**Splunk SPL:**
- Use index and sourcetype FROM THE SCHEMA — never guess
- Always use relative time: `earliest=-60m` or `earliest=-24h`
- End queries with `| head 20`
- NEVER use absolute timestamps
- Field names MUST match the schema exactly (case-sensitive)

**Elastic ESQL:**
- Use index pattern FROM THE SCHEMA
- Use `==` for equality (double equals)
- Quote keyword values: `"4624"` not `4624`
- Time: `WHERE @timestamp >= NOW() - 1 hour`
- End with `| LIMIT 20`
- Field names from schema (e.g., `event.code` not `EventCode`)

**Sentinel KQL:**
- Use table names FROM THE SCHEMA
- Use `==` for equality, `has` for word match, `contains` for substring
- Time: `| where TimeGenerated > ago(24h)`
- End with `| take 20`
- Field names from schema

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

1. **SCHEMA FIRST — NO EXCEPTIONS** — you MUST discover the SIEM schema before writing any investigation query. Never guess index names, sourcetypes, or field names. If you don't have the schema, ask for it.
2. **Use schema-verified names ONLY** — every index, sourcetype, and field in your queries must come from the schema discovery results. If a field doesn't exist in the schema, don't use it.
3. **Save schema to context immediately** — after schema discovery, save it so you never need to ask again for this conversation.
4. **Context is AUTHORITATIVE** — never contradict user-provided workspace context without concrete evidence
5. **Temporal investigation is MANDATORY** — always check what happened AFTER the alert event
6. **Classify EARLY** — after 1-3 initial queries, apply the classification framework
7. **Save context after each major step** — this enables resuming if the session is interrupted
8. **Post the final report as an assistant message** so it appears in the frontend conversation
9. **Never fabricate query results** — only use data the user has provided
10. **Follow the 9-section report format** from `references/report-format.md`
11. **TP does not equal confirmed malware** — True Positive means the alert correctly identified suspicious activity requiring response
