# Investigation Principles

## Core Principles

1. **ACTIVITY-BASED CLASSIFICATION** — Classification is determined by whether the SPECIFIC ACTIVITY is malicious, not by correlation or context alone.

2. **SEPARATION OF CLASSIFICATION AND CORRELATION** — Classification and correlation are separate questions. Correlation can NEVER override classification.

3. **RESOURCE OWNERSHIP DETERMINES LEGITIMACY** — When an actor owns a resource and the action is within its purpose, the activity is inherently legitimate.

4. **CORRELATION INFORMS ESCALATION, NOT CLASSIFICATION** — Correlation findings inform escalation decisions, not classification verdicts.

5. **TWO SEPARATE OUTPUTS** — Every alert produces two independent determinations: Classification (TP/FP/RI) AND Escalation (Yes/No + Reason).

6. **INVESTIGATE, CLASSIFY, REPORT** — Single unified workflow. Classify early, then refine.

7. **TEMPORAL INVESTIGATION IS MANDATORY** — Always check what happened AFTER the alert event.

8. **DISCOVERY NEEDS FOLLOW-UP** — Discovery commands REQUIRE checking for persistence/execution.

9. **ARCHIVED FILES ENUMERATION** — Each file is a potential IOC and MUST be individually reported.

10. **SERVER + DOWNLOAD = ESCALATE** — Browser downloads on servers require authorization documentation.

11. **BEC HAS NO PAYLOAD** — Don't dismiss email as FP just because it lacks malicious attachment/URL.

12. **CREDENTIAL LEAKS** — The AFFECTED account domain matters, not the leak source domain.

13. **CROSS-SOURCE FINDINGS** — If you query another log source and find related activity, those findings MUST appear in the report.

14. **ATTACK CHAIN NARRATIVE** — Section 5 "How" must tell the FULL story across ALL sources.

15. **TP != CONFIRMED MALWARE** — True Positive means the alert correctly identified suspicious activity requiring response, not proof of malware.
