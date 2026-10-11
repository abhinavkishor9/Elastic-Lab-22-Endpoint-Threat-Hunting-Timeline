# Lab 22 — Endpoint Threat Hunting with Elastic Timeline

## Overview

This lab demonstrates an evidence-driven endpoint threat-hunting workflow using Elastic Cloud, Elastic Agent, Kibana Discover, and ES|QL. The investigation focuses on chronological analysis of Windows endpoint events, Sysmon process-creation telemetry, PowerShell execution, and the availability of scheduled-task audit events.

The objective is to determine what the collected telemetry establishes, identify events that deserve further examination, and document visibility limitations without assuming that suspicious activity necessarily represents a compromise.

## Lab Environment

- **Operating System:** Windows 11 Pro
- **Endpoint:** `DESKTOP-9MMM37V`
- **Endpoint Monitoring:** Elastic Agent 9.5.4
- **Management:** Elastic Cloud Fleet
- **Data View:** `logs-*`
- **Event Source:** `windows.sysmon_operational`, with other available Elastic datasets
- **Query Language:** ES|QL
- **Investigation Interface:** Kibana Discover and Elastic Security Timeline, where available

## Objectives

- Verify Elastic Agent health and Fleet connectivity.
- Identify available event datasets and event codes.
- Hunt for Sysmon process-creation events.
- Examine PowerShell process execution and command-line context.
- Search for Windows scheduled-task creation and modification events.
- Organize relevant observations into a chronological investigation timeline.
- Document troubleshooting findings and distinguish confirmed evidence from unresolved questions.
- Apply MITRE ATT&CK mappings only when supported by observed behavior.

## Investigation Scope

The investigation examined endpoint telemetry available in the `logs-*` data view. Queries covered event-dataset inventory, Sysmon Event ID 1, PowerShell process execution, and Windows Security Event IDs 4698 and 4702.

The investigation also encountered a Fleet check-in failure caused by a reported hostname-resolution error. Subsequent DNS and TCP connectivity tests succeeded, and a later Elastic Agent status check reported Fleet as healthy and connected.

## Key Observations

- The dataset inventory query processed approximately 3.4K documents.
- `windows.sysmon_operational` Event ID 1 had 692 matching documents in the inventory results.
- `windows.sysmon_operational` Event ID 13 had 537 matching documents in the inventory results.
- The Sysmon process-creation query processed 107 documents and displayed 100 results.
- The PowerShell process query processed 100 documents and displayed 100 results.
- A process-creation result recorded `wevtutil.exe` running as `SYSTEM` at `2026-10-11 05:29:18.267`.
- The scheduled-task query for event codes 4698 and 4702 returned no matching documents in the examined query scope.
- A later status check confirmed that Elastic Agent was running and Fleet was connected.

These observations establish telemetry visibility and query results, not a confirmed security incident. In particular, the `wevtutil.exe` process event does not, by itself, prove that a Windows event log was cleared.

## Investigation Workflow

1. Verify Elastic Agent and Fleet status.
2. Confirm that recent endpoint telemetry is available.
3. Inventory event datasets and event codes.
4. Investigate Sysmon process-creation events.
5. Examine PowerShell execution and command-line details.
6. Search for scheduled-task creation and modification events.
7. Review related events chronologically and investigate their context.
8. Record evidence, telemetry limitations, troubleshooting actions, and follow-up recommendations.

## Evidence and Limitations

The findings are based on the observed query outputs and status checks. Results are limited by the selected time range, available fields, event collection configuration, and the data returned by each query.

A query returning no matches does not establish that the corresponding activity never occurred. Likewise, a process name, command line, or event code should not be treated as proof of malicious intent without corroborating evidence.

## Conclusion

This lab demonstrates a practical endpoint threat-hunting workflow using Elastic telemetry and ES|QL. It emphasizes service-health verification, process investigation, chronological analysis, and careful interpretation of event data.

The investigation did not establish a confirmed compromise. Its principal outcome is a documented assessment of the available endpoint telemetry, observed process activity, and areas requiring further validation.

## MITRE ATT&CK References

Potentially relevant techniques may be considered during follow-up analysis, provided the underlying evidence supports them:

- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1053 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

These are investigation references, not confirmed technique detections from this lab.
