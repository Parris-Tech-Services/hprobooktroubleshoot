# Windows Doctor — 100-item upgrade roadmap

This is the canonical product backlog derived from a September 2026 comparison against ten mature crash, hang and system-diagnostics tools.

**Brand & naming:** Public user-facing brand is **Windows Doctor**. Technical identifiers (`WindowsCrashDoctor.exe`, `desktop/WindowsCrashDoctor.App`, `windows-crash-doctor/` modules) are retained internally for backward compatibility.  
**Status:** **13 of 100 items completed and verified with automated tests** (`WCD-002`, `WCD-003`, `WCD-005`, `WCD-011`, `WCD-018`, `WCD-021`, `WCD-022`, `WCD-023`, `WCD-061`, `WCD-062`, `WCD-063`, `WCD-064`, `WCD-065`); **87 items remain open**. Completing an item requires implementation **and** a regression/acceptance test.  
**Priorities:** `P0` = core diagnostic reliability, `P1` = high-value expansion, `P2` = advanced/productisation.  
**Evidence rule:** new automation must preserve the current rule that observation, interpretation and causality are separate concepts.

## Definition of done

A roadmap item is not complete until it has:
1. a documented input/output contract;
2. explicit privacy and privilege behaviour;
3. a Windows regression test or fixture where practical;
4. bounded failure behaviour when evidence is unavailable;
5. documentation in `windows-crash-doctor/README.md`;
6. no automatic high-risk remediation without explicit user approval.

## WinDbg

Inspiration: Microsoft's full Windows debugger: native/user/kernel dump analysis, symbols, stacks, registers, live debugging and scripting.

- [ ] **WCD-001 [P0]** Add native parsing for Windows minidump, kernel dump and full-memory dump formats.
- [x] **WCD-002 [P0]** Add Microsoft symbol-server support with a configurable local symbol cache.
- [x] **WCD-003 [P0]** Add automatic bugcheck and exception decoding comparable to `!analyze -v`.
- [ ] **WCD-004 [P0]** Extract and rank kernel call stacks from crash dumps. The cdb/DbgEng backend can attempt kernel dumps, but this remains open until a real kernel crash-dump acceptance fixture proves unwind correctness end-to-end.
- [x] **WCD-005 [P0]** Add user-mode dump analysis with per-thread call stacks.
- [ ] **WCD-006 [P1]** Extract loaded modules from dumps, including image path, version, timestamp and vendor metadata.
- [ ] **WCD-007 [P1]** Expose register/context records from the faulting thread and processor.
- [ ] **WCD-008 [P1]** Add dump-time lock, wait-chain and deadlock analysis for hang cases.
- [ ] **WCD-009 [P2]** Map stack frames to function names and source file/line information when symbols are available.
- [ ] **WCD-010 [P2]** Add a WinDbg hand-off command that opens a selected dump with prepared symbol/source paths and scripted commands.

## WhoCrashed

Inspiration: A user-friendly crash-dump analyser that turns dump internals into likely problem families and next-step guidance.

- [x] **WCD-011 [P0]** Add one-command discovery and analysis of all crash dumps on the machine.
- [ ] **WCD-012 [P0]** Add remote crash-dump analysis for another Windows computer over an explicitly configured administrative path.
- [ ] **WCD-013 [P2]** Allow analysis of any user-selected dump directory, not only Crash Doctor collection folders.
- [ ] **WCD-014 [P1]** Generate uptime and time-since-boot context for every crash record.
- [ ] **WCD-015 [P1]** Add symbolized kernel stack summaries to the human-readable report.
- [ ] **WCD-016 [P1]** Add a dedicated loaded-modules-at-crash view.
- [ ] **WCD-017 [P2]** Add configurable Microsoft symbol server and local symbol-store settings.
- [x] **WCD-018 [P0]** Classify conclusions into bounded problem families such as driver, hardware, thermal, memory corruption and software.
- [ ] **WCD-019 [P2]** Build a maintained knowledge base for rare, obscure and vendor-specific bugchecks.
- [ ] **WCD-020 [P2]** Attach vetted troubleshooting and vendor-support links to findings when a known signature is matched.

## BlueScreenView

Inspiration: A lightweight historical BSOD/minidump browser focused on bugchecks, loaded drivers and stack-involved modules.

- [x] **WCD-021 [P0]** Add a historical crash table that indexes every discovered minidump chronologically.
- [x] **WCD-022 [P0]** Show bugcheck name, code and all four bugcheck parameters in a compact crash card.
- [x] **WCD-023 [P0]** Enumerate addresses in each crash stack and map them back to candidate drivers/modules.
- [ ] **WCD-024 [P1]** Extract driver version-resource metadata such as product, company, description and file version.
- [ ] **WCD-025 [P1]** Show the complete loaded-driver list for each selected crash.
- [ ] **WCD-026 [P1]** Add a focused view containing only drivers/modules actually referenced by the crash stack.
- [ ] **WCD-027 [P2]** Support reading minidumps from a remote UNC path.
- [ ] **WCD-028 [P2]** Support analysing an offline Windows installation by selecting its Minidump and system paths.
- [ ] **WCD-029 [P2]** Integrate DumpChk as an optional independent parser/cross-check when installed.
- [ ] **WCD-030 [P2]** Add drag-and-drop/single-file analysis for an arbitrary `.dmp` or `.mdmp` file.

## ProcDump

Inspiration: A trigger-driven dump-capture tool for hangs, exceptions, CPU/memory thresholds and difficult intermittent process failures.

- [ ] **WCD-031 [P0]** Add a CPU-high trigger that captures a process dump after a configurable sustained threshold.
- [ ] **WCD-032 [P2]** Add a CPU-low trigger for stalls where a target unexpectedly stops doing work.
- [ ] **WCD-033 [P1]** Add a process-memory/commit threshold trigger.
- [ ] **WCD-034 [P1]** Add arbitrary Windows performance-counter triggers.
- [ ] **WCD-035 [P0]** Add hung-window detection and automatic dump capture.
- [ ] **WCD-036 [P0]** Add unhandled-exception and optional first-chance-exception dump capture.
- [ ] **WCD-037 [P2]** Add dump-on-process-termination monitoring.
- [ ] **WCD-038 [P2]** Add wait-for-process and launch-and-monitor modes for intermittent application failures.
- [ ] **WCD-039 [P1]** Add configurable dump count, cooldown and trigger duration so repeated faults can be sampled safely.
- [ ] **WCD-040 [P2]** Add DLL load/unload and thread create/exit trigger modes for hard-to-reproduce application failures.

## WPR/WPA

Inspiration: Microsoft's ETW recording and timeline-analysis toolkit for CPU, I/O, memory, power, GPU and boot/resume scenarios.

- [ ] **WCD-041 [P0]** Add optional Event Tracing for Windows (ETW) capture as a first-class evidence source.
- [ ] **WCD-042 [P1]** Ship built-in recording profiles for CPU, disk I/O, file I/O, registry, network, memory, power and GPU scenarios.
- [ ] **WCD-043 [P2]** Support custom `.wprp` profiles for model/application-specific investigations.
- [ ] **WCD-044 [P0]** Add boot, Fast Startup, shutdown, reboot, standby and hibernate transition tracing.
- [ ] **WCD-045 [P0]** Capture CPU sampling, context switches, DPCs, ISRs and call stacks for pre-freeze analysis.
- [ ] **WCD-046 [P0]** Add disk/file I/O latency timelines rather than only point-in-time storage counters.
- [ ] **WCD-047 [P0]** Add memory, hard-fault, commit and working-set timelines.
- [ ] **WCD-048 [P0]** Add power, idle-state, sleep-state and battery/energy timelines.
- [ ] **WCD-049 [P2]** Create an interactive timeline/graph viewer with linked tables for correlated evidence.
- [ ] **WCD-050 [P0]** Support circular in-memory ETW buffers that can be flushed after an incident to preserve the minutes before failure.

## Process Monitor

Inspiration: High-volume, real-time file/Registry/process/thread/DLL tracing with stacks, filters and boot logging.

- [ ] **WCD-051 [P2]** Add real-time file-system operation capture with process attribution.
- [ ] **WCD-052 [P2]** Add real-time Registry operation capture with process attribution.
- [ ] **WCD-053 [P2]** Add real-time process and thread lifecycle capture.
- [ ] **WCD-054 [P2]** Add DLL/image-load activity capture.
- [ ] **WCD-055 [P2]** Capture per-operation thread stacks with optional symbol resolution.
- [ ] **WCD-056 [P2]** Add non-destructive filtering so analysts can change filters without losing the underlying captured trace.
- [ ] **WCD-057 [P2]** Add early-boot/boot-time logging for operations that occur before normal user logon.
- [ ] **WCD-058 [P2]** Add a process-tree view for every process referenced by a trace.
- [ ] **WCD-059 [P2]** Add a scalable native trace/backing-file format suitable for millions of events without keeping them all in memory.
- [ ] **WCD-060 [P2]** Record reliable process identity context for events: image path, command line, parent, user and session.

## Windows Error Reporting

Inspiration: Windows' native crash/hang reporting, local dump, report-store and application recovery infrastructure.

- [x] **WCD-061 [P0]** Read and index the local Windows Error Reporting report stores.
- [x] **WCD-062 [P0]** Parse `.wer` files and WER signatures, report IDs and bucket IDs.
- [x] **WCD-063 [P0]** Audit current global and per-application LocalDumps configuration.
- [x] **WCD-064 [P0]** Offer an explicit, reversible helper for enabling per-application LocalDumps after user approval.
- [x] **WCD-065 [P0]** Capture and catalogue user-mode crash dumps produced by WER.
- [ ] **WCD-066 [P1]** Detect and ingest WER application-hang/no-response reports.
- [ ] **WCD-067 [P2]** Track WER report lifecycle state, including queued, archived, uploaded and purged reports where available.
- [ ] **WCD-068 [P2]** Read and explain WER policy/consent settings and relevant Group Policy overrides.
- [ ] **WCD-069 [P2]** Surface Application Recovery and Restart registrations/configuration when diagnosing applications that crash or hang.
- [ ] **WCD-070 [P2]** Add a privacy-reviewed export bundle that can package Crash Doctor evidence for vendor/developer support without automatic upload.

## Fedora ABRT

Inspiration: Fedora's automatic crash detection/reporting stack with local problem storage, deduplication, retracing and analytics.

- [ ] **WCD-071 [P0]** Add an always-on crash-detection service rather than requiring manual snapshot collection.
- [ ] **WCD-072 [P2]** Add desktop and console notifications when a new crash/hang incident is detected.
- [ ] **WCD-073 [P0]** Create a persistent local problem database with lifecycle state instead of loose report files.
- [ ] **WCD-074 [P1]** Generate automatic backtraces when a supported dump/core format is available.
- [ ] **WCD-075 [P0]** Deduplicate repeated crashes using stable signatures and stack similarity.
- [ ] **WCD-076 [P1]** Cluster similar incidents and show frequency/trend statistics across time.
- [ ] **WCD-077 [P2]** Support remote/off-device retracing so symbolization can happen without installing every symbol package locally.
- [ ] **WCD-078 [P2]** Add pluggable reporting backends such as GitHub Issues, Jira, email or webhook export.
- [ ] **WCD-079 [P2]** Add runtime-specific handlers for native applications, managed/.NET, Python and other interpreters.
- [ ] **WCD-080 [P2]** Map known crash signatures to existing issue trackers or knowledge-base entries before suggesting a new report.

## Ubuntu Apport

Inspiration: Ubuntu's automatic crash reporter with environment collection, package hooks, retracing and guided bug submission.

- [ ] **WCD-081 [P0]** Automatically collect OS, package/application version and hardware context at the moment of a crash.
- [ ] **WCD-082 [P1]** Add application/package-specific diagnostic hooks that can contribute custom evidence.
- [ ] **WCD-083 [P2]** Support non-crash problem types such as installer/update failures and service startup failures.
- [ ] **WCD-084 [P2]** Add a simple user-facing crash notification/details UI suitable for non-technical users.
- [ ] **WCD-085 [P2]** Generate pre-filled support/bug-report titles and structured summaries from the diagnosis.
- [ ] **WCD-086 [P0]** Add an explicit privacy-review screen showing exactly what data would be included before any export or submission.
- [ ] **WCD-087 [P1]** Support retracing with debug symbols when local symbols are unavailable.
- [ ] **WCD-088 [P2]** Identify the owning installed package/application for a crashed binary or module.
- [ ] **WCD-089 [P2]** Search a configured issue tracker for probable duplicates before creating a new report.
- [ ] **WCD-090 [P2]** Add generic uncaught-exception hooks for runtimes such as Python and .NET so application failures are captured without bespoke scripts.

## systemd-coredump/coredumpctl

Inspiration: Persistent crash catalogue and core-dump retrieval/debug workflow with metadata, retention and access controls.

- [ ] **WCD-091 [P0]** Maintain a queryable local crash catalogue with one row per incident and stable identifiers.
- [ ] **WCD-092 [P1]** Store rich per-crash metadata such as process ID, user, executable, command line and termination reason.
- [ ] **WCD-093 [P0]** Add filtering by time range, process, executable, incident type and other metadata fields.
- [ ] **WCD-094 [P0]** Track whether each dump is present, missing, truncated, inaccessible or deliberately not stored.
- [ ] **WCD-095 [P1]** Allow extraction of the raw dump belonging to a selected catalogue entry.
- [ ] **WCD-096 [P2]** Add a command to launch the preferred debugger directly on a selected crash.
- [ ] **WCD-097 [P2]** Support analysing imported/offline Crash Doctor archives rather than only the current machine.
- [ ] **WCD-098 [P2]** Enforce permissions-aware visibility so non-admin users cannot read crash artefacts belonging to other users by default.
- [ ] **WCD-099 [P0]** Add configurable retention, purge and disk-space policies for crash dumps, traces and canary data.
- [ ] **WCD-100 [P0]** Record dump truncation, size limits and capture failures as first-class evidence rather than silently treating missing data as absence of a crash.

## Delivery order

Rather than implementing all 100 in numerical order:

- **Phase A — make evidence richer:** dump parsing/symbols, WER ingestion, ETW circular capture, incident catalogue and retention.
- **Phase B — make conclusions stronger:** stack analysis, bugcheck knowledge, deduplication, historical correlation and package/driver identity.
- **Phase C — make capture proactive:** ProcDump-style triggers, automated crash detection, boot/resume traces and runtime hooks.
- **Phase D — make investigation usable:** timeline UI, report history, privacy review, remote/offline workflows and guided support export.
- **Phase E — make it extensible:** plugins, custom profiles, reporting backends, retracing and debugger integrations.

The ProBook remains the first golden regression case, but no generic rule may assume HP-specific facts unless a profile explicitly supplies them.
