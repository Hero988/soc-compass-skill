# SIEM Query Guides

## Splunk SPL

### Rules
- Always use relative time: `earliest=-60m` or `earliest=-24h`
- NEVER use absolute timestamps
- End queries with `| head 20` (limit results)
- Default index: `index=main sourcetype=_json` (adjust per schema)
- Use field names from schema discovery results

### Common Patterns
```spl
# Process creation events
index=main sourcetype=WinEventLog EventCode=4688 earliest=-24h
| table _time ComputerName User NewProcessName CommandLine ParentProcessName
| head 20

# Network connections from a host
index=main sourcetype=WinEventLog dest_ip!=10.* dest_ip!=192.168.* earliest=-24h
| where src_ip="SUSPECT_IP"
| table _time src_ip dest_ip dest_port app
| head 20

# Authentication events
index=main sourcetype=WinEventLog (EventCode=4624 OR EventCode=4625) earliest=-24h
| table _time ComputerName TargetUserName LogonType IpAddress
| head 20

# File creation events
index=main sourcetype=WinEventLog EventCode=11 earliest=-24h
| where TargetFilename LIKE "%suspicious%"
| table _time Image TargetFilename
| head 20
```

### Temporal Follow-up Pattern
```spl
# What happened AFTER the alert (within 15 minutes)
index=main sourcetype=WinEventLog earliest="{alert_time}" latest="+15m@m"
| where ComputerName="{host}"
| table _time EventCode NewProcessName CommandLine ParentProcessName
| head 20
```

## Elastic ESQL

### Rules
- Start with `FROM <index-pattern>`
- Use `==` for equality (double equals)
- Quote keyword field values as strings: `"4624"` not `4624`
- Time filter: `WHERE @timestamp >= NOW() - 1 hour`
- End with `| LIMIT 20`
- Backslashes in LIKE need quadruple escaping: `\\\\`

### Common Patterns
```esql
# Process creation
FROM .ds-winlogbeat-*
| WHERE event.code == "1" AND @timestamp >= NOW() - 24 hours
| KEEP @timestamp, host.name, user.name, process.executable, process.command_line, process.parent.executable
| LIMIT 20

# Network connections
FROM .ds-winlogbeat-*
| WHERE event.code == "3" AND @timestamp >= NOW() - 24 hours
| WHERE source.ip == "SUSPECT_IP"
| KEEP @timestamp, source.ip, destination.ip, destination.port
| LIMIT 20
```

## Sentinel KQL

### Rules
- Start with table name directly: `SecurityEvent`, `SigninLogs`, etc.
- Use `==` for equality, `has` for word match, `contains` for substring
- Time: `| where TimeGenerated > ago(24h)`
- End with `| take 20`
- Default timestamp field: `TimeGenerated`

### Common Patterns
```kql
// Process creation
SecurityEvent
| where EventID == 4688 and TimeGenerated > ago(24h)
| project TimeGenerated, Computer, Account, NewProcessName, CommandLine, ParentProcessName
| take 20

// Authentication
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != "0"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription
| take 20

// Network connections
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SourceIP == "SUSPECT_IP"
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort, Activity
| take 20
```
