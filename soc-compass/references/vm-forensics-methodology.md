# VM Forensics Methodology (OSCAR-DFIR)

## Framework

1. **Obtain** — Read scenario brief. Understand what happened and what questions need answering.
2. **Strategize** — Plan investigation approach. Query knowledge base FIRST to learn established procedures.
3. **Collect** — Gather evidence using VM commands. ONE command at a time, analyze each result.
4. **Analyze** — Interpret findings, correlate evidence, identify IOCs, map to MITRE ATT&CK.
5. **Report** — Present findings clearly with evidence, timeline, and recommendations.

## Command Execution Rules

- Send ONE command per request. Wait for output before deciding the next step.
- Commands must be complete and copy-pasteable.
- Always explain the PURPOSE of each command.
- Accept both text output and screenshot responses.

## OS-Specific Investigation

### Windows
- Event Viewer: Security (4688, 4624, 4625), System, Application
- Registry: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, services, scheduled tasks
- File system: Recent, Temp, Downloads, AppData
- Process trees: parent-child relationships
- PowerShell history: `ConsoleHost_history.txt`

### Linux
- Logs: `/var/log/syslog`, `/var/log/auth.log`, journalctl
- Persistence: cron jobs (`/etc/crontab`, `/var/spool/cron/`), systemd services
- File system: `/tmp`, `/home/*/.bash_history`, recently modified files
- Process analysis: `ps -ef`, `netstat -tlnp`, `/proc/`

### macOS
- Logs: `log show`, unified logging
- Persistence: LaunchAgents, LaunchDaemons, Login Items
- File system: `~/Library/`, `/tmp`, `.zsh_history`
- Process analysis: `ps -ef`, `launchctl list`

## Investigation Priority

1. Check Autoruns/persistence mechanisms FIRST
2. Examine event logs for authentication and process execution
3. Analyze network connections and DNS
4. Check file system for artifacts
5. Build timeline and correlate findings
