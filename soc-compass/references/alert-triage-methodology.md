# Alert Triage Methodology

## 3-Phase Investigation Approach

### Phase 1: Initial (1-3 tool calls)
1. Run 1-2 queries to understand the alert
2. Optionally check IOCs for obvious indicators
3. Then apply the classification framework — do NOT keep gathering evidence indefinitely

### Phase 2: Classification (mandatory after Phase 1)
- Apply dual-hypothesis analysis
- Use the decision matrix below
- Target 85%+ confidence threshold

### Phase 3: Continuation (only if gaps identified)
- Gather SPECIFIC evidence to close identified gaps
- Re-apply classification with new evidence
- Maximum 2 re-classification attempts

## Dual-Hypothesis Analysis

### Hypothesis A — Legitimate (False Positive)
Evidence indicators:
- Matches documented operation in workspace context
- Vendor-signed from legitimate installation path
- Expected parent process
- Authorization exists (ticket, policy, scheduled task)
- Historical consistency (baseline behavior)
- No malicious follow-up activity

### Hypothesis B — Malicious (True Positive)
Evidence indicators:
- Malicious follow-up activity (execution, network, exfiltration)
- Suspicious indicators (double extensions, obfuscation, unusual timing)
- IOC hits (ThreatFox, AlienVault, URLScan)
- No authorization found
- Deviates from baseline
- Matches MITRE ATT&CK pattern

## Decision Matrix

| Benign Indicators | Malicious Indicators | Verdict | Confidence |
|---|---|---|---|
| 3+ | <2 | False Positive | 85-95% |
| <2 | 3+ | True Positive | 85-95% |
| 2+ | 2+ | Requires Investigation | 70-80% |
| <2 | <2 | Insufficient Evidence | <70% |

## Context Authority Rule

User-provided context is AUTHORITATIVE. It can only be contradicted with:
1. Concrete technical evidence (not patterns)
2. IOC hits with HIGH confidence
3. Explicit reasoning explaining why context should be overridden

## Temporal Investigation (MANDATORY)

Always check what happened AFTER the alert event:

| Alert Type | What to Check | Time Window |
|---|---|---|
| File Download | Extraction, execution | +5 to +15 min |
| Process Spawn | Children, network, files | +5 to +15 min |
| Network Activity | Follow-up connections | +5 to +15 min |
| Authentication | Post-login actions | +15 to +60 min |

## Alert-Specific Checkpoints

### Brute Force / Password Spray
- Threshold: >=5 attempts in <=10 minutes
- Check post-success activity if any attempt succeeded

### Defense Evasion / Security Tool Modification
- Is the modifying process the legitimate security product itself?
- Running from expected installation directory?
- If YES to 2+ indicators: likely FALSE POSITIVE

### Phishing / Suspicious Email
- Check for test/simulation indicators first
- Non-routable TLD check: both parties on same .thm/.local = FALSE POSITIVE
- Real phishing needs malicious payloads + unrelated sender

### Archive / File Download
- Archives are PRESUMED SUSPICIOUS until proven benign
- Check extracted file types (HIGH-RISK: .exe, .dll, .ps1, .bat, .vbs)
- Check post-extraction execution within 15 minutes
- Server + archive download + no authorization = TRUE POSITIVE + Escalate

## Negative Finding Documentation

A query that returns NO results is still a finding:
- "Queried [source] for [activity] from [time1] to [time2]. No matching events found." → report in Gaps Addressed
- Data source unavailable → report in Open Questions
