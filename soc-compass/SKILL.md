---
name: soc-compass
description: Conducts security investigations on SOC Compass. The AI agent reads workspace context, asks the user to run SIEM queries, analyzes results, and writes verdicts. Use when the user mentions SOC Compass, security investigations, alert triage, SIEM queries, threat analysis, Splunk, Elastic, Sentinel, IOC lookups, or investigation workspaces. Do not use for general cybersecurity questions not involving the SOC Compass platform.
---

# SOC Compass API

The agent acts as the SOC analyst: reading workspace context, formulating SIEM queries, asking the user to execute them, analyzing results, and writing verdicts to the SOC Compass platform.

## How to call the API

**ALWAYS use `curl` via the Bash tool.** Do not use WebFetch, fetch(), or any other HTTP client.

```bash
API="https://astute-cormorant-480.convex.site/api/v1"
KEY="<user-provided-api-key>"
curl -s "$API/ENDPOINT" -H "Authorization: Bearer $KEY"
```

Key format: `soc_sk_<32hex>`. The user provides this when invoking the skill.

### Posting multi-line content (Windows compatibility)

When posting reports or multi-line content, ALWAYS serialize via Node.js to avoid JSON escaping failures:

```bash
node -e "
const content = \`Your multi-line report here...\`;
process.stdout.write(JSON.stringify({role: 'assistant', content}));
" > /tmp/payload.json
curl -s -X POST "$API/conversations/$CONV/messages" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d @/tmp/payload.json
```

**NEVER** attempt to inline multi-line markdown directly in `curl -d '...'` on Windows. Backslashes, quotes, and newlines will break.

## CRITICAL: Schema discovery is MANDATORY

**You MUST discover the SIEM schema BEFORE writing ANY investigation query.** Do NOT guess index names, sourcetypes, or field names. Every SIEM instance is different. If you skip this step, your queries WILL fail.

The schema tells you:
- What **indexes** exist (e.g., `corp`, `main`, `wineventlog`)
- What **sourcetypes** exist (e.g., `WinEventLog`, `_json`, `xmlwineventlog`)
- What **fields** are available and their exact names (e.g., `EventCode` vs `event.code`)
- How many events each field/index contains

**Without the schema, you are blind. ALWAYS get the schema first.**

Schema is **per-workspace** (same SIEM instance). If you already have it from a prior conversation in the same workspace, you do NOT need to re-ask. Save it to context on first discovery.

## Analytical integrity

**When you reach a classification based on evidence, DEFEND IT.** If the user questions your verdict:

1. Restate the specific evidence supporting your classification
2. Ask what counter-evidence they have that you may have missed
3. Only change your classification if NEW evidence is presented
4. Never change a verdict just because the user disagrees — agreement without evidence is worse than being wrong with reasoning

A SOC analyst who flips their verdict without new evidence is unreliable. The user may be testing your conviction or playing devil's advocate.

## Classification decision framework

Classify based on the **SPECIFIC activity the alert detected**, not the overall host state:

- Alert fires on Event X → Is Event X **itself** malicious/suspicious?
  - YES → **True Positive**
  - NO → **False Positive** (even if other malicious activity exists on the host)

Example: Alert fires on a legitimate scheduled task creation. During investigation you discover a DIFFERENT malicious task on the same host.
- The alert = **False Positive** (it detected a legitimate task)
- The malware = **separate finding requiring its own alert/escalation**
- Note both findings in the report, but classify the alert based on what IT detected

This is NOT "the alert was useless" — the alert LED to discovering the malware. But classification is about the specific detected activity.

## Automated scenarios

### Scenario A: New investigation

User gives alert + workspace ID. Follow these steps **in exact order**:

**Step 1: Get workspace context**
```bash
curl -s "$API/workspaces/{workspaceId}" -H "Authorization: Bearer $KEY"
```
Note the `siemProvider` (splunk/elastic/sentinel), `mode`, `contextInput`, and `dataSource`.

**Step 2: Create or select conversation**

If this alert is part of an already-investigated incident (same host, same attack chain, same timeframe), **append to the existing conversation** instead of creating a new one. Otherwise, create a new conversation:

```bash
curl -s -X POST "$API/workspaces/{workspaceId}/conversations" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"title": "Investigation: {alertTitle}", "eventId": "{alertId}"}'
```

**Step 3: Check for cached context**
```bash
curl -s "$API/conversations/{CONV_ID}/context" -H "Authorization: Bearer $KEY"
```
If `agentContext` has a `schema` field → you already have the schema, skip to Step 5.
If `agentContext` is null → fresh investigation, proceed to Step 4.

**Step 4: MANDATORY schema discovery**

This step is NON-NEGOTIABLE. You MUST do this before ANY investigation query.

Ask the user directly based on the SIEM provider from Step 1:

**Splunk:**
> Please run this query in Splunk and paste the **full results**:
> ```
> index=* NOT index=_* earliest=-30d | head 10000 | fieldsummary maxvals=10 | sort -count | head 60
> ```
> This will show me what indexes, sourcetypes, and fields exist so I can write accurate queries.

**Elastic:**
> Please go to Kibana Discover, select the relevant index pattern, and paste **5-10 sample events** as JSON. I need the actual field names to write correct ES|QL queries.

**Sentinel:**
> Please run this in Azure Monitor Logs and paste the results:
> ```
> search * | summarize count() by $table | sort by count_ desc | take 20
> ```
> Then paste **3-5 sample events** from the most relevant table.

After the user provides schema results:
1. **Parse carefully** — extract index names, sourcetypes, field names, event counts
2. **Save immediately** to context so you never need to ask again:
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"schema": {"provider": "splunk", "indexes": [...], "sourcetypes": [...], "fields": [...], "rawSchemaOutput": "..."}, "investigationPhase": "schema_complete"}'
```
3. **ALL subsequent queries MUST use names from the schema.** Never guess or use defaults.

**Step 5: Investigation loop**

NOW you can formulate queries — using ONLY field names, indexes, and sourcetypes from the schema.

For each query:
1. Verify the fields exist in the schema
2. Use the correct index and sourcetype from the schema
3. Ask the user to run it:

> Please run this {SPL/KQL/ESQL} query and paste the results:
> ```
> {query using schema-verified field names}
> ```
> **Purpose:** {why this query matters}

Analyze results. Apply the classification framework after 1-3 initial queries.

**Step 6: Write verdict**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/verdict" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"eventId": "{alertId}", "verdict": "True Positive", "confidence": 92, "severity": "high", "escalationRequired": true, "classificationRationale": "..."}'
```

Valid verdicts: `True Positive`, `False Positive`, `Suspicious`, `Requires Further Investigation`, `Unknown`

**Step 7: Post report** (use Node.js serialization — see "Posting multi-line content" above)

Use the 9-section report format (see `references/report-format.md`):
1. Executive Summary 2. Alert Details 3. Investigation Findings 4. Classification (verdict + rationale + H1/H2 evidence) 5. Critical Findings 6. IOCs (table) 7. Affected Entities 8. MITRE ATT&CK 9. Recommendations

**Step 8: Save full context**
```bash
curl -s -X POST "$API/conversations/{CONV_ID}/context" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d '{"schema": {...}, "queriesRun": [...], "iocs": [...], "mitreTechniques": [...], "keyFindings": [...], "verdict": {...}, "investigationPhase": "completed"}'
```

### Scenario B: Resume investigation

User references a conversation ID:
```bash
curl -s "$API/conversations/{CONV_ID}/context" -H "Authorization: Bearer $KEY"
```
Read saved context (schema, queries, findings). Resume from where you left off. No need to re-read messages or redo schema discovery.

### Scenario C: General question

User asks a question (not a full investigation):
1. Read workspace context for relevant info
2. Answer directly
3. Save Q&A in conversation context

### Scenario D: Extra context

User provides info beyond what's in the workspace. Save it alongside investigation state in context.

### Scenario E: Related alert (same host/incident)

If the new alert is clearly part of an already-investigated incident (same host, same timeframe, same attack chain):

1. **DO NOT create a new conversation** — append to the existing one
2. Skip schema discovery (already cached in context)
3. Reference prior findings: "This was already identified during Alert {X} investigation"
4. Post verdict and report as additional messages in the same conversation
5. Only create a new conversation if the alert is on a different host or a genuinely separate incident

## Multi-alert workflow

When the user says "first alert" or implies multiple alerts:

1. Ask upfront: "How many alerts are there? Are they on the same host?"
2. If same host/timeframe: plan to use a single conversation for related alerts
3. Schema discovery only needs to happen ONCE per workspace
4. For subsequent alerts on the same host, check if existing investigation already covers the activity before running new queries
5. When an alert is simply a different view of already-investigated activity, classify it based on the evidence already gathered — no redundant queries needed

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

## Decoding encoded commands

When you find PowerShell `-EncodedCommand` or other Base64 payloads, decode immediately:

```bash
echo '<base64_string>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```

Always decode and present the decoded content to the user. Encoded commands are critical evidence.

## Investigation modes

Auto-detected from the workspace `mode` field:

**Alert Triage** (`ultimate_trigger`, default):
Dual-hypothesis analysis — evaluate both benign and malicious explanations. Apply classification framework after 1-3 queries. See `references/alert-triage-methodology.md`.

**SOC Investigation** (`soc_investigation_trigger`):
Broader scope, SIEM optional, evidence-first approach.

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
| `GET` | `/conversations/:id/messages?limit=N` | Message history (max 100) |
| `POST` | `/conversations/:id/messages` | Post message (user/assistant) |
| `PUT` | `/conversations/:id/messages/:msgId` | Edit message content |
| `DELETE` | `/conversations/:id/messages/:msgId` | Delete message |
| `GET` | `/conversations/:id/context` | Get agent context |
| `POST` | `/conversations/:id/context` | Save agent context (overwrite) |
| `PATCH` | `/conversations/:id/context` | Merge-update context |
| `GET` | `/conversations/:id/verdict` | Read verdicts |
| `POST` | `/conversations/:id/verdict` | Write verdict (upserts by eventId) |
| `GET` | `/conversations/:id/status` | Processing status |

All endpoints require `Authorization: Bearer soc_sk_<key>` except `/health`.

**Verdict POST behavior:** If a verdict already exists for the same eventId in the conversation, it will be updated (upsert). You can safely re-post a verdict to correct it.

## Error codes

| Code | Status | Meaning |
|------|--------|---------|
| `bad_request` | 400 | Invalid input (check JSON syntax) |
| `unauthorized` | 401 | Invalid/expired API key |
| `not_found` | 404 | Resource not found |
| `rate_limited` | 429 | Too many requests (60/min standard) |
| `internal_error` | 500 | Server error |

## Critical rules

1. **SCHEMA FIRST — NO EXCEPTIONS** — discover the SIEM schema before ANY investigation query. Never guess index names, sourcetypes, or field names.
2. **Use schema-verified names ONLY** — every index, sourcetype, and field must come from schema discovery.
3. **Save schema to context immediately** — so you never need to ask again for this workspace.
4. **DEFEND your classifications** — only change a verdict when NEW evidence is presented, not because the user disagrees. Restate your evidence and ask for counter-evidence.
5. **Classify the SPECIFIC activity** — an alert that fires on legitimate activity is FP even if unrelated malicious activity exists on the same host. Report both, classify separately.
6. **Reuse conversations for same-incident alerts** — don't mechanically create new conversations for every alert.
7. **Temporal investigation is MANDATORY** — always check what happened AFTER the alert event.
8. **Classify EARLY** — after 1-3 initial queries, apply the classification framework.
9. **Save context after each major step** — enables resume if the session is interrupted.
10. **Post the final report as an assistant message** so it appears in the frontend.
11. **Use Node.js for JSON serialization** on Windows — never inline multi-line content in curl -d.
12. **Never fabricate query results** — only use data the user has provided.
13. **TP does not equal confirmed malware** — True Positive means the alert correctly identified suspicious activity requiring response.
