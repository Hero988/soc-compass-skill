---
name: soc-compass
description: Conducts security investigations on SOC Compass. The AI agent reads workspace context, asks the user to run SIEM queries, analyzes results, and writes verdicts. Supports multiple alerts in parallel via subagent dispatch. Use when the user mentions SOC Compass, security investigations, alert triage, SIEM queries, threat analysis, Splunk, Elastic, Sentinel, IOC lookups, investigation workspaces, or multiple alerts. Do not use for general cybersecurity questions not involving the SOC Compass platform.
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

Reports contain Windows paths like `C:\Users\luke.s\AppData\...` where `\T`, `\0`, etc. break Node.js template literals. Use this **two-step file-based method** instead:

```bash
# Step 1: Write report to file using heredoc (handles all escaping including backslashes)
cat > "$TEMP/report.txt" << 'ENDOFREPORT'
Your report with C:\paths\and\backslashes goes here...
ENDOFREPORT

# Step 2: Read file and JSON-stringify with Node.js (use cygpath for Windows paths)
REPORT_PATH="$(cygpath -w "$TEMP/report.txt")"
PAYLOAD_PATH="$(cygpath -w "$TEMP/payload.json")"
node -e "
const fs = require('fs');
const content = fs.readFileSync(process.argv[1], 'utf8');
fs.writeFileSync(process.argv[2], JSON.stringify({role: 'assistant', content}));
" "$REPORT_PATH" "$PAYLOAD_PATH"

# Step 3: Post using the JSON file
curl -s -X POST "$API/conversations/$CONV/messages" \
  -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
  -d @"$PAYLOAD_PATH"
```

**CRITICAL Windows notes:**
- **NEVER** use Node.js template literals (backticks) for content with Windows paths — `\0` triggers "Legacy octal escape" errors
- **NEVER** use `/tmp/` paths with Node.js on Windows — Node.js resolves `/tmp/` as `C:\tmp\` which doesn't exist. Always use `$TEMP` with `cygpath -w` to convert to Windows paths
- The heredoc with `'ENDOFREPORT'` (single-quoted delimiter) prevents ALL bash escaping — safe for any content

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

Note: `earliest=-30d` limits to the last 30 days — good for production SIEMs to avoid scanning too much data. For TryHackMe labs or historical investigations where events may be older, the autonomous mode uses `earliest=0` (All time) instead.

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

**HITL mode (default):** Ask the user to run each query:
> Please run this {SPL/KQL/ESQL} query and paste the results:
> ```
> {query using schema-verified field names}
> ```
> **Purpose:** {why this query matters}

**Autonomous mode:** Run each query yourself via Chrome — type the query in the SIEM search bar, execute it, and read the results directly.

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

Alerts can arrive at any time — the user should NOT have to wait for one investigation to finish before sending the next. Handle this with **subagent dispatch**.

### Subagent dispatch (recommended for multiple alerts)

When the user sends a new alert while you're working on a previous one, or sends multiple alerts:

1. Use the **Agent tool** to spawn a subagent for each alert investigation
2. Pass the subagent: API key, workspace ID, SIEM URL (if autonomous), alert details, and cached schema (if available)
3. The subagent independently handles the full investigation: schema discovery → queries → analysis → verdict → report → context save
4. The main session stays immediately available for new alerts
5. Run subagents **in the background** (`run_in_background: true`) so you can keep accepting new alerts

**HITL mode:** Multiple subagents can run in parallel — each asks the user for query results independently.

**Autonomous/Chrome mode:** Only one subagent can use Chrome at a time. Queue additional alerts and dispatch them when the current Chrome investigation completes.

### Related alerts (same host/incident)

If a new alert is clearly part of the same incident (same host, same timeframe, same attack chain):
- Append to the existing conversation instead of creating a new one (Scenario E)
- Skip schema discovery (already cached)
- Reference prior findings — don't re-run queries for already-investigated activity
- Schema discovery only needs to happen ONCE per workspace

### Batch mode (alternative)

User can also paste ALL alerts in a single message. Process each sequentially, reusing schema and conversation for related alerts (same host).

### Completion signals

After each alert investigation, clearly signal completion:
> "Alert {ID} investigation complete. Verdict: {verdict}. Ready for the next alert."

This helps the user know when it's safe to review results and when to send more alerts.

## Asking the user for information (HITL mode — default)

In the default human-in-the-loop mode, ask the user DIRECTLY in the conversation:

- "Please run this query in your {Splunk/Elastic/Sentinel}: `{query}`"
- "Please check this IOC in VirusTotal/ThreatFox: `{ioc}`"
- "Is this server authorized to make outbound connections to external IPs?"

Guidelines:
- Ask ONE query at a time (user runs manually)
- Always explain the PURPOSE of each query
- If user provides partial results, ask for clarification
- If user can't run a query, adapt your approach
- Save context after each major step (enables resume)

**Note:** If the user requested autonomous mode, skip asking — use Chrome to run queries directly (see "Autonomous Mode" section below).

## Autonomous Mode (Chrome Integration)

**This mode is OPTIONAL and OPT-IN ONLY.** Only activate when the user EXPLICITLY requests automation. If the user does not mention automation, Chrome, autonomous, or browser — use the default HITL mode above and DO NOT mention autonomous mode.

### When to activate

Activate autonomous mode ONLY when the user's message contains phrases like:
- "do this autonomously" / "automate this" / "fully automated"
- "use my browser" / "use Chrome"
- "run the queries yourself" / "you do it"
- "here's the Splunk/Kibana/Sentinel URL, go ahead"
- "no human in the loop" / "don't ask me to run queries"

If none of these phrases appear, **stay in HITL mode silently**. Do not suggest or mention autonomous mode.

### Prerequisites

Before using autonomous mode, verify:

1. **Chrome is connected** — the user must have launched Claude Code with `claude --chrome` or typed `/chrome`. If Chrome tools are not available, tell the user:
   > "Autonomous mode requires Chrome integration. Please run `/chrome` to connect your browser, then try again. Make sure you're logged into the target websites first."

2. **User is logged in** — the AI uses the user's existing Chrome sessions. It cannot log in, handle MFA, or solve CAPTCHAs. If a login page appears, pause and ask the user to log in manually.

### How to use Chrome tools

Use the browser tools provided by the `claude-in-chrome` MCP to interact with websites:

- **Navigate**: Open a URL in a new tab or navigate the current tab
- **Read**: Read the page content, tables, form values
- **Click**: Click buttons, links, menu items
- **Type**: Type text into search boxes, form fields
- **Screenshot**: Take a screenshot to verify what you see
- **Multiple tabs**: Open different sites in different tabs (e.g., Splunk in one, VirusTotal in another)

### Autonomous investigation flow

Follow the same investigation steps as HITL mode, but instead of asking the user to run queries, run them yourself via Chrome.

**Reading results:** Use `get_page_text` instead of screenshots for extracting complete data (hashes, encoded commands, long field values). Screenshots are useful for visual verification but lose critical details like full SHA256 hashes and base64 strings. For Splunk, click into the Events tab and use `get_page_text` to read full event details.

**Schema discovery (Splunk):**

Use URL-based navigation (most reliable — avoids CodeMirror editor interaction issues):

1. Navigate directly to: `{splunk_url}/en-US/app/search/search?earliest=0&latest=&q=search%20index%3D*%20NOT%20index%3D_*%20%7C%20head%2010000%20%7C%20fieldsummary%20maxvals%3D10%20%7C%20sort%20-count%20%7C%20head%2060&display.page.search.tab=statistics`
2. Wait for results to load
3. Use `get_page_text` to read the results table
4. Save schema to SOC Compass context via API

Note: `earliest=0&latest=` sets the time range to "All time" — essential for historical data (TryHackMe labs, past incidents). The default "Last 24 hours" will return nothing for historical events.

**Schema discovery (Kibana/Elastic):**
1. Navigate to the Kibana URL → Discover
2. Select the relevant index pattern
3. Set time range to cover the investigation period
4. Use `get_page_text` to read 5-10 sample events
5. Save schema to context

**Schema discovery (Sentinel):**
1. Navigate to the Azure Portal Log Analytics workspace
2. Run: `search * | summarize count() by $table | sort by count_ desc | take 20`
3. Use `get_page_text` to read results, then query sample events from the relevant table
4. Save schema to context

**Running investigation queries (Splunk — URL method, recommended):**

Navigate directly with the query in the URL instead of typing in the search bar:

```
{splunk_url}/en-US/app/search/search?earliest=0&latest=&q=search%20{url_encoded_query}&display.page.search.tab=events
```

Steps:
1. URL-encode your SPL query
2. Navigate to the URL above with the encoded query
3. Wait for results to load
4. Use `get_page_text` to read the full results (Events tab for raw events, Statistics tab for table output)
5. Analyze and formulate next query
6. Repeat

**Why URL-based is better than typing in the search bar:**
- Splunk's CodeMirror editor often fails with `form_input` — text appends instead of replacing
- Ctrl+A sometimes selects the whole page instead of just the query
- URL-based execution is 100% reliable and also sets the time range correctly

**Running investigation queries (Kibana/Sentinel):**
1. Navigate to the query interface
2. Clear and type the new query
3. Execute and use `get_page_text` to read results
4. Analyze and repeat

**IOC lookups via Chrome:**
1. Open a new tab
2. Navigate to VirusTotal (https://www.virustotal.com), ThreatFox, or other threat intel site
3. Search for the hash/IP/domain
4. Use `get_page_text` to read the results and detection ratios
5. Include findings in the investigation

**Handling errors:**
- If a **login page** appears: pause and ask the user to log in manually, then continue
- If a **CAPTCHA** appears: pause and ask the user to solve it, then continue
- If the **page doesn't load** or times out: try refreshing, then ask the user for help
- If **results are still loading**: wait and check again (SIEM queries can take time)
- If **CodeMirror/search bar interaction fails**: fall back to URL-based query execution

### Important: Still use the SOC Compass API

Even in autonomous mode, you MUST still:
- Save schema to conversation context via API
- Write the verdict via API
- Post the report as a message via API
- Save full investigation context via API

Chrome is used to GATHER evidence. The API is used to PERSIST results.

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
14. **Autonomous mode is OPT-IN ONLY** — never activate autonomous mode or mention Chrome unless the user explicitly requests automation. Default is always HITL mode.
