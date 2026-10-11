
# Timeline — Lab 22: Endpoint Threat Hunting with Elastic Timeline

## 1. Purpose

This document records selected endpoint observations and troubleshooting milestones from the investigation. It separates event timestamps reported by the endpoint from the order in which the investigation and connectivity checks were performed.

The available evidence does not establish that the listed process events belong to one attack chain.

## 2. Endpoint Event Timeline

| Timestamp (2026-10-11) | Host | User | Event | Observation |
|---|---|---|---|---|
| 05:29:18.267 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | `wevtutil.exe` process creation; PID 7448 |
| 05:40:30.029 | `DESKTOP-9MMM37V` | `Dell` | Sysmon Event ID 1 | `PickerHost.exe` process creation |
| 05:40:34.118 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | `powershell.exe` process creation |
| 05:40:39.315 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | `powershell.exe` process creation |
| 05:41:41.387 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | PowerShell process-creation query result |
| 05:41:46.569 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | PowerShell process-creation query result |
| 05:41:51.763 | `DESKTOP-9MMM37V` | `SYSTEM` | Sysmon Event ID 1 | PowerShell process-creation query result |

### Interpretation

The timestamps establish that the listed process-creation events were recorded by the endpoint telemetry. The available screenshots do not provide the complete command lines, parent-process relationships, or sufficient surrounding evidence to determine whether the events were related.

The `wevtutil.exe` observation requires additional examination. Its presence does not prove that Windows event logs were cleared.

The PowerShell events also require contextual review. PowerShell running as `SYSTEM` may be legitimate, depending on the process origin and execution purpose.

## 3. Telemetry Inventory Milestone

The event inventory query processed approximately 3.4K documents.

| Dataset | Event code | Reported count |
|---|---|---:|
| `windows.sysmon_operational` | `1` | 692 |
| `windows.sysmon_operational` | `13` | 537 |
| `elastic_agent.metricbeat` | Not populated in the displayed result | 336 |

These counts describe the inventory query output. They are not counts of unique processes, incidents, or malicious activities.

## 4. Investigation Milestones

The following entries document the sequence of investigation and troubleshooting actions. Exact times were not available for every action.

| Order | Action | Result |
|---|---|---|
| 1 | Checked Elastic Agent status | Agent was running, but Fleet check-in initially failed |
| 2 | Investigated the Fleet hostname | DNS resolution returned `34.67.5.185` |
| 3 | Flushed the Windows DNS cache | Subsequent hostname resolution succeeded |
| 4 | Repeated system-resolver tests | Five consecutive lookups succeeded |
| 5 | Tested TCP connectivity to port 443 | `TcpTestSucceeded : True` |
| 6 | Attempted to retrieve agent logs | CLI could not find the expected `logs\events` directory |
| 7 | Rechecked agent status | Fleet reported `HEALTHY Connected`; agent reported `HEALTHY Running` |
| 8 | Inventoried available event datasets | Sysmon process-creation and registry-related telemetry were visible |
| 9 | Investigated process-creation events | The query processed 107 documents and displayed 100 results |
| 10 | Investigated PowerShell execution | The query processed 100 documents and displayed 100 results |
| 11 | Searched for scheduled-task events | Event IDs 4698 and 4702 returned no matching documents in the examined scope |

## 5. Unresolved Questions

- What command-line arguments and parent process explain the observed `wevtutil.exe` execution?
- Were the observed PowerShell processes expected system or administrative activity?
- Is Windows Security auditing configured to record scheduled-task creation and modification?
- Are the relevant Security events being collected and indexed by Elastic?
- Why was the expected Elastic Agent `logs\events` directory unavailable to the CLI?
- Can additional correlated events establish a relationship between any of the observed processes?

These questions remain open until supported by further evidence.

## 6. Final Assessment

The investigation confirmed that endpoint process-creation telemetry was available and that Elastic Agent and Fleet were connected at the final status check. PowerShell events were visible, but the scheduled-task query returned no matching records within the examined scope.

No confirmed compromise or attack chain was established. The timeline is a record of observed telemetry and investigation milestones, not a claim that the endpoint experienced a security incident.

Further investigation should prioritize full event details, parent-child process relationships, command-line analysis, and validation of Windows Security event collection.
