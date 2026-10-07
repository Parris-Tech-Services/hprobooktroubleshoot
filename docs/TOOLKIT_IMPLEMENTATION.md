# Native technician toolkit

Open **Integrations → Technician toolkit**, or start `WindowsCrashDoctor.exe --toolkit`.

## Implemented

- All 208 catalog entries are searchable/filterable in a native WPF window, with official vendor/documentation links and licensing notes.
- 178 curated launcher/detection mappings search PATH, Windows system directories, WindowsApps aliases, registered installation locations, common program folders and Crash Doctor's provider directory. Missing tools are shown as unavailable; boot/cloud entries are distinguished. Portable or custom executables can be located explicitly and persist across app restarts.
- 73 curated diagnostic/action recipes show the exact command before execution. Read-only diagnostic output is captured with exit status, timestamps and bounded cancellation/timeout handling. Native nonzero exit codes remain failures.
- System-changing commands and diagnostics needing elevation open a user-selected visible PowerShell console. Administrator approval is requested when needed. A transcript is written locally; the application reports a handoff, not a successful repair. Reboots and long repairs are never triggered by opening the toolkit.
- WinDbg/cdb accepts a selected dump and the configured Microsoft symbol path. Symbol settings can be inspected or explicitly configured. Native dump analysis remains separately accessible through the existing diagnostic page.
- LibreHardwareMonitor offers the existing digest-verified installer, a current-sensor action and the existing deep-capture workflow. Preflight now checks the actual `Tools` installation directory. The Windows PowerShell generic-list return bug is fixed in the shipped adapter source.
- Every tool can attach an external report up to 100 MiB. The source remains untouched. A unique local evidence directory stores the copy, measured SHA-256, tool name/version, category and UTC import time. Reports are treated as external evidence, without inventing diagnostic conclusions.
- The latest toolkit evidence can be exported through the existing privacy review/redaction service. Raw/binary/unsupported files can be excluded; exclusions and redactions are displayed before export.

## Storage and boundaries

Catalog and commands are embedded build resources from `windows-crash-doctor/integrations/toolkit.tsv` and `toolkit-actions.json`. They are not downloaded runtime instructions. Update the action generator and regenerate definitions before building.

Local configured paths: `%LOCALAPPDATA%\WindowsCrashDoctor\toolkit-paths.json`. Local evidence: the user's Desktop `Windows Crash Doctor Results\Toolkit\<unique operation>`. Imports and traces are private by default. Executables chosen by the user must be trusted locally; the app does not assert that their contents or commercial licensing are verified.

Cloud services, AD tools and bootable utilities use vendor instructions, user-configured executable handoffs and report attachment. This change does not provision tenants, enroll remote agents, create boot media, execute erasure, certify ITAD operations or buy licences. Stress tests and external repair utilities remain user-operated after the selected launcher opens.

No generic external report is presented as an automatic diagnosis. Tool-specific parsers, authenticated APIs, long-running bench orchestration and certified erasure remain explicitly unchecked in [the integration TODO](TOOLKIT_INTEGRATION_TODO.md).

## Verification

The desktop `--self-test` includes catalog/resource coverage, installed built-in detection, read-only output capture, preservation of native exit failures, rejection of system-changing/unregistered read-only actions, report hash/provenance, preservation of source files, known-secret privacy review, import size limits and invalid local settings handling. Existing engine, process-timeout, comparison and privacy-export tests still run.

Build: `dotnet build desktop/WindowsCrashDoctor.App/WindowsCrashDoctor.App.csproj -c Release`. Publish: `dotnet publish desktop/WindowsCrashDoctor.App/WindowsCrashDoctor.App.csproj -c Release -r win-x64 --self-contained true`. Run the published executable with `--self-test` before installing it. Local builds must be labelled local builds rather than published verified releases.
