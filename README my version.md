# Elastic-Lab-22-Endpoint-Threat-Hunting-Timeline
## Overview
Endpoint threat hunting is the proactive process of examining endpoint telemetry to identify suspicious behavior that may not have generated a security alert. Instead of waiting for an alert, a SOC analyst investigates available events, looks for unusual patterns, and determines whether further investigation is justified.

The central concept is timeline-based investigation. Individual events often provide limited context, but arranging related events chronologically can help explain what happened before, during, and after a potentially suspicious action.
For example, consider this hypothetical sequence:
- A user launches PowerShell.
- PowerShell starts another process with unusual command-line arguments.
- The child process creates a scheduled task.
- Additional process activity occurs shortly afterward.
Individually, some of these events could be legitimate. When correlated by timestamp, process relationships, and other available fields, they may provide a stronger basis for deciding whether further investigation is necessary.

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

## Lab Objectives 

The objectives of this lab are to:

- Verify Elastic Agent health and Fleet connectivity before beginning an endpoint threat-hunting investigation.
- Examine available Elastic datasets and event codes to assess the endpoint's telemetry coverage.
- Use ES|QL to identify and investigate Sysmon process-creation events on a Windows endpoint.
- Analyze PowerShell execution by examining process names, executable paths, command-line arguments, parent processes, and timestamps.
- Investigate potentially relevant Windows activity, including scheduled-task creation or modification, while validating event availability and collection requirements.
- Construct a chronological sequence of endpoint observations using Elastic Security Timeline, where available, or Kibana Discover as an alternative.
- Correlate related events using host information, user context, process identifiers, parent-child relationships, and timestamps.
- Distinguish confirmed observations from suspicious indicators, investigative hypotheses, and unresolved questions.
- Map observed behaviors to relevant MITRE ATT&CK techniques only when supported by the collected evidence.
- Troubleshoot telemetry visibility and Fleet connectivity issues without making unnecessary changes to the existing Elastic Agent installation.
- Document investigation queries, key observations, evidence limitations, and recommended follow-up actions in a reproducible SOC investigation record.


## Lab Scenario 

A SOC analyst is asked to review endpoint telemetry from a Windows 11 workstation after routine monitoring highlights several process-execution events involving PowerShell and Windows utilities. The available logs contain process-creation records, user context, executable paths, and command-line information. However, the presence of these events alone does not establish malicious activity.

The analyst uses Elastic Security and ES|QL to investigate the available telemetry, determine which events provide useful investigative context, and establish a chronological view of relevant endpoint activity. The investigation begins by validating Elastic Agent and Fleet connectivity, then examining the available datasets and event codes to understand which sources can support the analysis.

## Investigation Tasks

- **Validate telemetry:** Confirm that Elastic Agent is running and connected to Fleet, then identify the Windows event datasets available for investigation.
- **Investigate process execution:** Examine Sysmon process-creation events, focusing on PowerShell and other potentially relevant Windows utilities.
- **Review execution context:** Compare timestamps, usernames, process identifiers, parent processes, executable paths, and command-line arguments where the fields are available.
- **Build a timeline:** Organize relevant observations chronologically in Elastic Security Timeline or use Kibana Discover if Timeline is unavailable.
- **Check investigative coverage:** Query for scheduled-task-related events and determine whether the available telemetry supports further analysis or whether additional collection is required.

## Investigation Constraints

The analyst must distinguish observed activity from assumptions. A PowerShell process, a Windows administrative utility, or an empty query result is not sufficient by itself to confirm malicious behavior or prove that an event did not occur. Findings must be based on the available records, and any missing fields or telemetry gaps must be documented.

The final investigation record should summarize the events examined, the queries used, the resulting timeline, and any limitations that affect the conclusions. Potential MITRE ATT&CK mappings may be included when supported by the evidence, but they must remain hypotheses unless the observed behavior justifies a stronger assessment.

## Expected Outcome

Produce a reproducible endpoint-hunting record that demonstrates how to examine Windows process activity, correlate relevant events, and build an evidence-based timeline using Elastic. The investigation should clearly separate confirmed observations, suspicious indicators, unresolved questions, and recommended follow-up actions without declaring a compromise unless the collected evidence supports that conclusion.

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

## MITRE ATT&CK References

Potentially relevant techniques may be considered during follow-up analysis, provided the underlying evidence supports them:

- [T1059.001 — PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [T1053 — Scheduled Task/Job](https://attack.mitre.org/techniques/T1053/)
- [T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

These are investigation references, not confirmed technique detections from this lab.

