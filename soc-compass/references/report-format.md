# Investigation Report Format (9 Sections)

## Section 1: Incident Summary
- Event ID, Rule Name, Severity, Timestamp
- Host/IP, User, Process Path, Parent Process, Command Line

## Section 2: Triage & Classification
- **Verdict**: True Positive / False Positive / Suspicious / Requires Further Investigation
- **Rationale**: 1-2 sentence summary
- **Escalation Required**: Yes/No + reason
- **Confidence**: Percentage (e.g., 92%)

## Section 3: Detailed Rationale
- **H1 (Benign) Evidence**: List each indicator with supporting evidence
- **H2 (Malicious) Evidence**: List each indicator with supporting evidence
- **Flip Conditions**: What new evidence would change the verdict

## Section 4: Linking Alerts & Patterns
- Related alerts in the same conversation/workspace
- MITRE ATT&CK technique mappings with evidence
- Historical patterns or baseline comparisons

## Section 5: Incident Details
- **Who**: User/account involved
- **What**: FULL file paths, command lines, process trees
- **Where**: Host, IP, network segment
- **When**: Timeline of events
- **Why Suspicious**: What triggered the alert
- **How**: Detailed mechanism across ALL sources where evidence was found

## Section 6: Indicators of Compromise (IOCs)

| IOC | Type | Verdict | Source |
|-----|------|---------|--------|
| 192.168.1.100 | IP | Suspicious | SIEM query |
| evil.example.com | Domain | Malicious | ThreatFox |
| abc123def456... | SHA256 | Unknown | File analysis |

For file-based alerts, include: filename, path, size, hash, risk level (HIGH/MEDIUM/LOW).

## Section 7: Recommended Actions
- **Immediate**: Block IOC, isolate host, disable account
- **Investigation**: Further queries to run, data to collect
- **Long-Term**: Rule tuning, process improvement, training

## Section 8: Conclusion
- Summary judgment (1-2 sentences)
- Next steps with owner and timeframe

## Section 9: Investigation Items
- **Gaps Addressed**: Questions answered during investigation (including negative findings)
- **Open Questions**: Unanswered questions that couldn't be resolved
- **Playbook Deviations**: Any departures from standard procedure with reasoning
