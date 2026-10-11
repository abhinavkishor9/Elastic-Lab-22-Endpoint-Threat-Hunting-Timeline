# Troubleshooting Notes 

## 1. Fleet Check-In Failure

### Symptom

Elastic Agent initially reported Fleet as failed while the local agent process remained healthy.

The error indicated that the agent could not check in to Fleet Server because hostname resolution failed:

    lookup fb3a130d457f49d0a559c1cee482757f.fleet.us-central1.gcp.elastic.cloud: no such host

### Initial Diagnosis

The failure occurred during DNS resolution, before the agent could establish its Fleet HTTPS connection. However, the error alone did not establish whether the cause was a temporary DNS problem, an incorrect hostname, or another resolver-related issue.

### Tests Performed

The Fleet hostname was tested using:

    Resolve-DnsName $hostName
    nslookup $hostName

The hostname resolved through a CNAME to:

    prd-gcpusc1-cp-app-2c.us-central1.gcp.elastic.cloud

The resolved IPv4 address was:

    34.67.5.185

The active Wi-Fi adapter used DNS servers `1.1.1.1` and `8.8.8.8`.

The local DNS cache was flushed using:

    ipconfig /flushdns

Subsequent DNS resolution succeeded. Five additional calls using the Windows system resolver all returned `34.67.5.185`.

TCP connectivity was then tested:

    Test-NetConnection $hostName -Port 443

The result was:

    TcpTestSucceeded : True

### Final Verification

A later command returned:

    fleet: HEALTHY Connected
    elastic-agent: HEALTHY Running

### Resolution and Assessment

Fleet connectivity recovered by the time of the later status check. DNS cache flushing and successful DNS and TCP tests were part of the troubleshooting sequence, but the available evidence does not establish that flushing the cache alone caused the recovery.

The original error may have reflected a transient resolution failure. The precise root cause remains unconfirmed.

### Lessons Learned

- A running Elastic Agent does not guarantee that Fleet check-ins are succeeding.
- Successful DNS resolution and TCP connectivity are separate checks from an actual Fleet check-in.
- Recheck agent status after each diagnostic step.
- Avoid reinstalling or re-enrolling an agent when connectivity may recover without such changes.

## 2. Elastic Agent Log Command Failure

### Symptom

The following command failed:

    & "C:\Program Files\Elastic\Agent\elastic-agent.exe" logs -n 100

The reported error stated that the CLI could not list the expected log directory:

    C:\Program Files\Elastic\Agent\data\elastic-agent-9.5.4+build202609161310-b18dae\logs\events

Windows reported that the specified path could not be found.

### Investigation

The agent data directory was inspected using `Get-ChildItem`. The versioned agent data directory was present, but the recursive directory search did not identify a usable `logs\events` directory.

### Assessment

The command could not retrieve logs from the expected location. This does not, by itself, prove that the entire Elastic Agent installation was corrupted or that event collection had stopped.

The agent later reported `HEALTHY` and Fleet reported `Connected`. Those status results demonstrate recovery of connectivity, but do not explain why the expected log directory was unavailable.

### Recommended Follow-Up

If the problem recurs:

1. Verify the service name, state, and executable path.
2. Inspect the exact versioned agent data directory.
3. Check which log directories and files actually exist.
4. Use the supported Elastic Agent diagnostics or diagnostic-bundle workflow for the installed version.
5. Preserve the agent data and configuration while investigating.

Do not create arbitrary internal directories, delete the agent's data directory, or reinstall the agent solely because this CLI command failed.

## 3. Scheduled-Task Query Returned No Results

### Symptom

The query for Windows Security Event IDs 4698 and 4702 returned zero matching documents.

### Possible Explanations

- No matching event occurred during the selected time range.
- The relevant Windows auditing policy was not enabled.
- Security event logs were not collected or indexed.
- The selected data view or event fields did not include the required records.
- Relevant events occurred outside the examined time range.

These are possible explanations, not confirmed causes.

### Recommended Checks

First, expand the Discover time range and verify the available Security event datasets.

On the authorized lab endpoint, inspect the relevant audit policy in elevated PowerShell:

    auditpol /get /subcategory:"Other Object Access Events"

If the required auditing is disabled, determine whether enabling it is appropriate for the lab and verify the resulting events through Windows Event Viewer or `Get-WinEvent`.

If a controlled test scheduled task is created, verify the event in the local Security log first, then confirm that Elastic collects and indexes it. Remove the test task after validation.

### Assessment

An empty query result is a telemetry or investigation finding, not proof that scheduled-task activity never occurred.

## 4. Process and PowerShell Query Results

### Observation

The Sysmon process-creation query returned 107 processed documents and displayed 100 results. The PowerShell query returned 100 processed documents and displayed 100 results.

### Interpretation

These results confirm that the queries matched endpoint telemetry. The result limits mean that the displayed records should not be treated as a complete historical inventory.

### Recommended Checks

- Expand the time range when a broader hunt is required.
- Inspect complete event documents rather than relying on truncated Discover columns.
- Review process parent information, command-line arguments, executable paths, and process identifiers.
- Confirm that the events belong to the intended host and time window.
- Correlate related activity before assigning a malicious interpretation.

## 5. Interpreting `wevtutil.exe`

### Observation

A Sysmon process-creation event recorded `wevtutil.exe` running as `SYSTEM` at `2026-10-11 05:29:18.267`.

### Assessment

`wevtutil.exe` is a legitimate Windows utility. The process name alone does not establish that an event log was cleared.

### Recommended Checks

Retrieve the complete process event and inspect the command line, parent process, and surrounding events. Search for relevant Windows event-log clearing records, such as Security Event ID 1102 or System Event ID 104, while validating the event provider and channel.

If corroborating evidence is unavailable, retain the observation as unresolved rather than reporting confirmed log clearing.

