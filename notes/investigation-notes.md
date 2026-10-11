
# Investigation Notes — Lab 22: Endpoint Threat Hunting with Elastic Timeline

## 1. Investigation Summary

The objective was to assess the endpoint telemetry available in Elastic Cloud and investigate Windows process activity using ES|QL. The hunt focused on dataset coverage, Sysmon process creation, PowerShell execution, and scheduled-task audit events.

During the investigation, Elastic Agent initially reported a failed Fleet check-in with a hostname-resolution error. DNS resolution and TCP connectivity were subsequently verified, and a later agent status check reported both Fleet and Elastic Agent as healthy.

The available data contained substantial Sysmon process-creation telemetry. However, the scheduled-task query returned no matching documents within the examined scope. The results support an assessment of telemetry availability, but they do not establish that a compromise or malicious persistence activity occurred.

## 2. Investigation Environment

- Endpoint: `DESKTOP-9MMM37V`
- Operating system: Windows 11 Pro
- Elastic Agent: 9.5.4
- Fleet status at final verification: Healthy / Connected
- Agent status at final verification: Healthy / Running
- Data view: `logs-*`
- Primary dataset: `windows.sysmon_operational`
- Query language: ES|QL

## 3. Dataset and Event Inventory

### Query

    FROM logs-*
    | STATS event_count = COUNT(*) BY event.dataset, event.code
    | SORT event_count DESC
    | LIMIT 100

### Observations

The query processed approximately 3.4K documents and returned an inventory of event datasets and event codes.

The visible results included:

| Dataset | Event code | Count |
|---|---:|---:|
| `windows.sysmon_operational` | `1` | 692 |
| `windows.sysmon_operational` | `13` | 537 |
| `elastic_agent.metricbeat` | Not populated in the displayed result | 336 |

Event ID 1 represents Sysmon process creation. Event ID 13 records registry value-setting activity in Sysmon.

### Assessment

The inventory confirmed that process-creation telemetry and registry-related telemetry were available in the indexed data. The inventory is useful for selecting subsequent hunt targets and understanding which event sources can support the investigation.

The inventory counts describe the results at the time of the query. They should not be interpreted as unique processes, unique incidents, or counts of malicious events.

## 4. Sysmon Process-Creation Hunt

### Query

    FROM logs-*
    | WHERE event.code == "1"
    | KEEP @timestamp, host.name, user.name,
           event.dataset, event.code,
           process.pid, process.name,
           process.executable, process.command_line
    | SORT @timestamp DESC
    | LIMIT 100

### Observations

The query processed 107 documents and displayed 100 results. The visible records belonged to `windows.sysmon_operational` on `DESKTOP-9MMM37V`.

Examples included process-creation events around:

- `2026-10-11 05:40:30.029` — `PickerHost.exe`, user `Dell`.
- `2026-10-11 05:40:34.118` — `powershell.exe`, user `SYSTEM`.
- `2026-10-11 05:40:39.315` — `powershell.exe`, user `SYSTEM`.

The screenshot showed truncated executable paths and did not provide sufficient context to determine why each process was launched.

### Assessment

The results confirm that Sysmon process-creation events were searchable for the endpoint. The presence of PowerShell under `SYSTEM` warrants examining the complete command line, parent process, and execution context, but does not establish malicious activity.

Because the query was sorted in descending timestamp order and limited to 100 results, it represents a bounded sample rather than a complete history of process execution.

## 5. PowerShell Process Investigation

### Query

    FROM logs-*
    | WHERE event.code == "1"
    | WHERE process.name IN ("powershell.exe", "pwsh.exe")
    | KEEP @timestamp, host.name, user.name,
           process.name, process.executable,
           process.command_line, process.parent.name
    | SORT @timestamp DESC
    | LIMIT 100

### Observations

The query processed 100 documents and displayed 100 results. The visible events included PowerShell executions on `DESKTOP-9MMM37V` at approximately:

- `2026-10-11 05:41:41.387`
- `2026-10-11 05:41:46.569`
- `2026-10-11 05:41:51.763`

The visible results showed `powershell.exe` running as `SYSTEM`. The displayed command-line text included a `NoProfile` argument, but the screenshot did not expose the complete command line.

### Assessment

The PowerShell query confirmed that PowerShell process events were available. The next step is to inspect the full event documents, including command lines, parent processes, executable paths, and process identifiers.

The observed `SYSTEM` account and PowerShell execution are not sufficient to classify the activity as malicious. A conclusion requires contextual evidence, such as the command's purpose, process ancestry, related file or network events, and whether the execution was expected.

## 6. `wevtutil.exe` Process Observation

### Observation

A Sysmon Event ID 1 result recorded:

- Timestamp: `2026-10-11 05:29:18.267`
- Host: `DESKTOP-9MMM37V`
- User: `SYSTEM`
- Process: `wevtutil.exe`
- Process ID: `7448`

### Assessment

`wevtutil.exe` is a legitimate Windows utility for working with event logs. Its presence in process telemetry does not prove that a log was cleared or modified.

The complete command line and surrounding events were not established by the supplied screenshot. The event should therefore be treated as an observation requiring context, not as a confirmed log-clearing event.

If further investigation is warranted, retrieve the full process event and examine the command-line arguments, parent process, and any corresponding Windows event-log records. Event ID 1102 or Event ID 104 should be interpreted in its provider and channel context if matching records are available.

## 7. Scheduled-Task Investigation

### Query

    FROM logs-*
    | WHERE event.code IN ("4698", "4702")
    | KEEP @timestamp, host.name, user.name,
           event.dataset, event.code, event.action
    | SORT @timestamp DESC

### Observation

The query returned zero matching documents in the examined scope.

### Assessment

The result does not establish that scheduled tasks were never created or modified. Potential explanations include the selected time range, unavailable audit events, missing event collection, or the absence of matching activity during the query scope.

Recommended validation:

1. Expand the time range to include the relevant investigation period.
2. Verify that Windows Security events are being collected.
3. Check whether the required audit policy is enabled.
4. Inspect the available Security dataset and event fields.
5. If necessary, generate a controlled test task on the authorized lab endpoint and verify whether the resulting event is recorded.

Do not report scheduled-task persistence as confirmed without supporting event details.

## 8. Timeline-Based Analysis

The available screenshots provide several timestamps that can guide further examination:

| Timestamp | Observation | Interpretation |
|---|---|---|
| `05:29:18.267` | `wevtutil.exe` process creation | Requires full command-line and surrounding-event review |
| `05:40:30.029` | `PickerHost.exe` process creation | Context not established |
| `05:40:34.118` | PowerShell process creation | Inspect parent process and complete command line |
| `05:40:39.315` | PowerShell process creation | Inspect parent process and complete command line |
| `05:41:41.387` | PowerShell process creation | Inspect full event details |
| `05:41:46.569` | PowerShell process creation | Inspect full event details |
| `05:41:51.763` | PowerShell process creation | Inspect full event details |

The supplied screenshots do not establish that these events form a single execution chain. Correlation requires matching context, not timestamps alone.

## 9. MITRE ATT&CK Assessment

Potential areas for follow-up include:

- **T1059.001 — PowerShell:** Relevant to PowerShell execution analysis. The observed process events alone do not establish an adversarial technique.
- **T1053 — Scheduled Task/Job:** Relevant if task creation or modification is established through appropriate event details. The current scheduled-task query returned no matches.
- **T1070.001 — Clear Windows Event Logs:** Relevant only if the evidence supports actual event-log clearing. The observed `wevtutil.exe` process event is insufficient to establish this behavior.

No ATT&CK technique should be reported as confirmed solely because a query targeted a related event ID or process name.

## 10. Conclusion and Follow-Up

The investigation confirmed that Elastic Agent and Fleet were connected at the final verification point and that Sysmon process-creation telemetry was available for the endpoint. PowerShell activity was visible, while the scheduled-task query returned no matching events in the examined scope.

The investigation did not establish a confirmed compromise. Further work should retrieve full process-event details, validate Windows Security event collection, and correlate any relevant records before drawing conclusions about suspicious behavior.

The primary lesson is to use endpoint telemetry to construct and test an evidence-based explanation rather than infer an attack from an isolated process or an empty query result.
