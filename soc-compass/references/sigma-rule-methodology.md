# Sigma Rule Engineering Methodology

## Capabilities
- Write production-ready Sigma rules from natural language descriptions
- Tune existing rules to reduce false positives
- Validate syntax, logic, and field/modifier usage
- Convert to SPL, KQL, ESQL
- Map to MITRE ATT&CK techniques

## Sigma YAML Structure

```yaml
title: Descriptive Title
id: <UUID v4>
status: test | experimental | stable
description: What this rule detects and why
author: Author Name
date: YYYY-MM-DD
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    FieldName: value
    FieldName|modifier: value
  filter:
    FieldName: value
  condition: selection and not filter
falsepositives:
  - Known false positive scenarios
level: informational | low | medium | high | critical
```

## Critical: YAML Key Uniqueness

YAML cannot have duplicate keys. This causes silent data loss:

**WRONG (duplicate keys):**
```yaml
selection:
  CommandLine|contains: '-urlcache'
  CommandLine|contains:        # OVERWRITES above!
    - 'http://'
```

**CORRECT (combine or use different keys):**
```yaml
selection:
  CommandLine|contains:
    - '-urlcache'
    - 'http://'
```

Or use separate selections:
```yaml
selection_flags:
  CommandLine|contains|all:
    - '-urlcache'
selection_url:
  CommandLine|contains:
    - 'http://'
condition: selection_flags and selection_url
```

## Common Logsource Categories

| Category | Product | Service | Key Fields |
|----------|---------|---------|------------|
| `process_creation` | windows | sysmon/security | Image, CommandLine, ParentImage |
| `network_connection` | windows | sysmon | DestinationIp, DestinationPort |
| `file_event` | windows | sysmon | TargetFilename, Image |
| `registry_set` | windows | sysmon | TargetObject, Details |
| `dns_query` | windows | sysmon | QueryName, Image |

## Conversion to SIEM Languages

### SPL (Splunk)
```
index=* sourcetype=WinEventLog:Security EventCode=4688
| where CommandLine LIKE "%suspicious_pattern%"
```

### KQL (Sentinel)
```
SecurityEvent
| where EventID == 4688
| where CommandLine contains "suspicious_pattern"
```

### ESQL (Elastic)
```
FROM .ds-winlogbeat-*
| WHERE event.code == "4688"
| WHERE process.command_line LIKE "*suspicious_pattern*"
```
