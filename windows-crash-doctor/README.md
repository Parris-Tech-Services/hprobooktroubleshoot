# Windows Crash Doctor

Windows Crash Doctor is an evidence-first Windows crash/hang triage engine.

The project has two analysis paths:
- **snapshot analysis** — consumes a reproducible collector folder, evaluates bounded diagnostic rules and can correlate optional HWiNFO sensor telemetry plus Windows System Power Reports;
- **dump analysis** — parses supported Windows crash-dump structures directly and emits Markdown + JSON.

The app is being expanded through the [100-item roadmap](../docs/ROADMAP_100.md). Roadmap status must distinguish shipped capability from partial/in-progress work.

## What problem it solves

Windows failure investigations commonly mix together:
- the failure itself;
- events written only after the reboot;
- old or future-dated events inherited from a cloned/refurb image;
- speculation about a suspicious driver;
- several simultaneous “fixes”.

Crash Doctor tries to stop that. A finding must distinguish:
- **evidence** — what was actually captured;
- **interpretation** — what that evidence reasonably supports;
- **confidence** — how reliable that interpretation is;
- **severity** — how urgently it matters;
- **next step** — the smallest useful follow-up action.

## Requirements

- Windows 10/11 or Windows Server capable of running Windows PowerShell 5.1+.
- Administrator rights are recommended for the collector; analysis can run with ordinary file access to the evidence/dump.
- No third-party PowerShell modules are required at runtime by the snapshot, telemetry or native dump parser.

## Snapshot-analysis quick start

From the repository root in an elevated PowerShell session:

```powershell
.\scripts\collect-diagnostics.ps1
```

Then:

```powershell
.\windows-crash-doctor\Invoke-CrashDoctor.ps1 `
  -EvidencePath "$env:USERPROFILE\Desktop\HPProBook-YYYYMMDD-HHMMSS"
```

To include an existing HWiNFO sensor export in the same snapshot:

```powershell
.\scripts\collect-diagnostics.ps1 `
  -SensorCsvPath "$env:USERPROFILE\Desktop\sensors.CSV"
```

The collector copies the supplied CSV to `sensors.csv`; it does not start, configure or modify HWiNFO.

To place reports elsewhere:

```powershell
.\windows-crash-doctor\Invoke-CrashDoctor.ps1 `
  -EvidencePath C:\Evidence\HPProBook-20260912-160000 `
  -OutputDirectory C:\Evidence\Reports
```

## Dump-analysis quick start

To parse an individual Windows dump:

```powershell
.\windows-crash-doctor\Invoke-CrashDoctor.ps1 `
  -DumpPath C:\Windows\Minidump\example.dmp
```

Optional output directory:

```powershell
.\windows-crash-doctor\Invoke-CrashDoctor.ps1 `
  -DumpPath C:\Evidence\example.dmp `
  -OutputDirectory C:\Evidence\Reports
```

Dump mode writes:
- `crash-doctor-dump-report.md`;
- `crash-doctor-dump-report.json`.

## WCD-001 native dump parser status

**WCD-001 is in progress, not complete.** The current foundation is intentionally useful without overstating coverage.

### Implemented

For `MDMP` minidumps Crash Doctor currently parses:
- header + stream directory with bounds validation;
- processor architecture and Windows build information;
- exception thread/code/address/parameters when present;
- loaded-module list and module names;
- thread count and thread stack memory descriptors (`MINIDUMP_THREAD`);
- candidate driver addresses active on the crash stack mapped to module names (`WCD-023`);
- bounded problem family classification: `Driver`, `Hardware`, `MemoryCorruption`, `StorageFileSystem`, `PowerThermal`, `SystemSoftware` (`WCD-018`);
- `MemoryList`, `Memory64List` and `MemoryInfoList` summary metadata;
- known stream names while retaining unknown stream IDs.

For Windows kernel crash-dump containers Crash Doctor currently recognises:
- 64-bit `PAGE` / `DU64` headers;
- 32-bit `PAGE` / `DUMP` headers;
- machine architecture;
- processor count;
- bugcheck code and four parameters;
- bounded problem family classification (`WCD-018`);
- key dump-header pointers/metadata;
- 64-bit dump-type/size/time metadata where available.

## Windows Error Reporting & LocalDumps (`WerDoctor.psm1`)

Windows Doctor provides comprehensive native diagnostics for Windows Error Reporting (WER) and user-mode application crashes:

- **WER store indexing (`WCD-061`)**: Indexes both user (`%LOCALAPPDATA%\Microsoft\Windows\WER`) and system (`%ProgramData%\Microsoft\Windows\WER`) report archives and queues.
- **WER report parsing (`WCD-062`)**: Parses `.wer` files into structured records extracting EventType, FILETIME timestamps, Bucket IDs, Application Name/Version, Fault Module, and Exception Code (`0x...`).
- **LocalDumps configuration audit (`WCD-063`)**: Inspects global and per-application `LocalDumps` registry keys (`HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`), verifies dump folder existence, write permissions, and available disk space.
- **Reversible dump configuration (`WCD-064`)**: Provides `Set-CrashDoctorLocalDumps` and `Remove-CrashDoctorLocalDumps` with `-WhatIf` dry-run preview, privilege verification, and explicit rollback commands.
- **User-mode crash catalogue (`WCD-065`)**: Automatically catalogues user-mode crash dumps in configured LocalDumps folders and WER directories, cross-referencing minidump streams with `.wer` event records.

### Still required before WCD-001 is complete

- validated traversal of kernel/full-memory dump page data;
- broader coverage of dump variants across Windows versions/architectures;
- real kernel/full-memory fixtures, not only synthetic headers;
- additional corruption/truncation fuzz cases;
- a stable documented dump JSON schema once the native structures settle.

Symbol resolution, deep stack unwinding and source mapping are tracked in `WCD-002`, `WCD-004`, `WCD-005`, and `WCD-009`.

## Snapshot outputs

### `crash-doctor-report.md`

Designed for a person investigating the machine. It contains:
- inventory/coverage;
- detected findings;
- severity/confidence;
- bounded interpretation;
- next diagnostic action;
- telemetry summary when supported sensor/power evidence is present.

### `crash-doctor-report.json`

The machine-readable automation boundary for snapshot analysis. External tooling should consume JSON rather than scrape Markdown.

Breaking schema changes should increment `SchemaVersion`.

## Current snapshot rule families

| Area | Current capability |
|---|---|
| Firmware | Detect firmware-class failed-start/Code 10 and current OK state |
| Image provenance | Detect Sysprep/respecialisation and retained non-present-device state |
| OEM/tuning | Detect XTU and Conexant-related evidence without claiming causality |
| BitLocker | Report conversion context without treating repeated percentages as proof of a stall |
| Power | Identify hibernation/Fast Startup state from collected evidence |
| Crash capture | Identify weak pagefile/dump configuration |
| Storage | Interpret current Windows storage reliability counters conservatively |
| Events | Summarise WHEA, Kernel-Power 41 and volmgr 161 |
| Sensor telemetry | Parse HWiNFO-style CSVs, including duplicate headers, and assess RAM pressure, thermal/WHEA state, drive flags, sample gaps and combined workload bursts |
| System Power Report | Parse `LocalSprData`, count only failure records inside the report's declared time window, and identify abnormal shutdowns/bugchecks without accepting stale/future records as current |
| Reporting | Markdown + JSON |

## Telemetry interpretation

Sensor and power-report data is time-bounded evidence:
- sustained high RAM load can explain paging/stalls without proving a hard-reset mechanism;
- low temperatures and zero throttle flags weaken overheating only for the captured interval;
- a zero HWiNFO WHEA counter is bounded negative evidence, not a hardware guarantee;
- brief GPU/ring electrical-limit flags remain low-priority unless they line up with failures;
- a continuous sensor log argues against a hidden freeze during that exact capture;
- System Power Report failure sessions are filtered to `ReportStartTime..ScanTime` before being counted.

The final rule matters on reused/refurbished images where inherited or clock-corrupted records can otherwise create false crash histories.

## Current limitations

Crash Doctor still does **not**:
- resolve Microsoft symbols;
- unwind native/kernel call stacks;
- inspect dump-time locks/deadlocks;
- fully traverse arbitrary kernel/full-memory dump pages;
- fully decode arbitrary binary `.evtx` files inside the snapshot rule engine;
- record ETW/WPR traces;
- monitor process exceptions/hangs continuously;
- maintain a persistent incident database;
- deduplicate repeated crashes across many snapshots;
- show an interactive timeline;
- ingest the complete WER report store;
- send reports to a bug tracker or vendor.

These are explicitly tracked in [`../docs/ROADMAP_100.md`](../docs/ROADMAP_100.md).

## Safety boundary

The analysis path is read-only. Diagnostic recommendations are not the same as authorised remediation.

Crash Doctor must not silently:
- flash BIOS/UEFI;
- install/uninstall drivers;
- disable BitLocker or security controls;
- change dump/pagefile policy;
- disable hibernation;
- run Driver Verifier;
- upload dump files, ETL traces, sensor logs or private evidence.

Crash dumps can contain process memory, credentials, document fragments and identifiers. Event logs and diagnostic snapshots can also contain user/account information. Parsing is local-only by default; generated reports still require review before publication.

## Input contract

The canonical collector remains:

```powershell
.\scripts\collect-diagnostics.ps1
```

Crash Doctor treats missing evidence as **unknown**, not healthy. A partial collection should reduce `Coverage` rather than generate confident negative findings.

Optional snapshot telemetry inputs in the evidence directory:
- `sensors.csv`, `sensor*.csv` or `hwinfo*.csv` — HWiNFO-style sensor export;
- `systempower-report*.html` or `sleepstudy-report*.html` — Windows System Power Report/SleepStudy data.

The collector already generates `systempower-report.html`. Binary EVTX files are preserved locally for deeper work; the current snapshot core still primarily consumes its text event exports.

Dump mode accepts one local file path and rejects unknown signatures, impossible ranges and truncated structures rather than silently guessing.

## Testing and QA

Repository QA runs on `windows-latest` and currently includes:
- Windows PowerShell parser checks across all `.ps1`/`.psm1` sources;
- PSScriptAnalyzer error gate;
- existing snapshot-analysis synthetic self-test;
- telemetry regression test with duplicate HWiNFO headers, memory/thermal/WHEA/drive checks and an out-of-window future bugcheck that must be ignored;
- WCD-001 synthetic binary minidump/x64-kernel/x86-kernel fixtures;
- invalid/truncated dump rejection;
- dump CLI Markdown/JSON integration check;
- a **real Windows DbgHelp `MiniDumpWriteDump` smoke test** of the CI PowerShell process;
- integration self-test;
- Pester integration suite;
- public-evidence/recovery-key guard.

Useful local commands:

```powershell
.\windows-crash-doctor\tests\self-test.ps1 -RepositoryMode
.\windows-crash-doctor\tests\telemetry-self-test.ps1
.\windows-crash-doctor\tests\dump-parser-test.ps1
.\windows-crash-doctor\tests\dump-parser-real-smoke.ps1
.\windows-crash-doctor\tests\integration-self-test.ps1 -RepositoryMode
```

There is currently **no browser UI**, so Playwright is not an appropriate whole-app test runner yet. Browser E2E tests should be added when an HTML/web UI exists; the present product surface is PowerShell CLI + generated Markdown/JSON.

## Design principles

1. Understand before changing.
2. One concept, one source of truth.
3. Collection and remediation are separate.
4. Missing data is unknown, not proof of health.
5. Event 41 and abnormal-shutdown records are aftermath evidence, not root-cause labels.
6. Historical Windows-image state is not automatically current-machine state.
7. A suspicious component is a hypothesis until discriminating evidence supports it.
8. Prefer controlled A/B tests over batches of changes.
9. Every finding should be reproducible from named evidence.
10. Privacy, retention and provenance are diagnostic features, not documentation afterthoughts.

## Where the project is going

The ten-tool benchmark in [`../docs/COMPARABLE_TOOLS_RESEARCH.md`](../docs/COMPARABLE_TOOLS_RESEARCH.md) produced 100 concrete upgrades spanning:
- native dump analysis and symbols;
- trigger-based capture;
- ETW timelines;
- ProcMon-style activity correlation;
- WER ingestion;
- automatic crash detection;
- history/deduplication;
- privacy review and retention;
- remote retracing;
- debugger and issue-tracker integrations.

Use [`../docs/README.md`](../docs/README.md) as the documentation index.
