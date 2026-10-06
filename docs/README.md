# Documentation index

This repository has two kinds of documentation and they should not be confused:

1. **Product documentation** — how Windows Crash Doctor works, how to use it, and what is planned.
2. **Case documentation** — evidence and reasoning for the HP ProBook 11 G2 hard-freeze investigation.

## Start here

| Need | Document |
|---|---|
| Understand the whole repository | [`../README.md`](../README.md) |
| See the live/public case dashboard source | [`../index.html`](../index.html) |
| See the purchase, seller assessment and honest eBay-review wording | [`PURCHASE_SELLER_AND_EBAY_REVIEW.md`](PURCHASE_SELLER_AND_EBAY_REVIEW.md) |
| See the safe cross-chat ProBook case history | [`../conversation/CONSOLIDATED_CASE_HISTORY_2026-09-15.md`](../conversation/CONSOLIDATED_CASE_HISTORY_2026-09-15.md) |
| See the current engineering quality/risk audit and highest-priority fixes | [`REPOSITORY_AUDIT.md`](REPOSITORY_AUDIT.md) |
| See what was implemented for the audit's Phase 0 blockers | [`PHASE0_IMPLEMENTATION_2026-09-12.md`](PHASE0_IMPLEMENTATION_2026-09-12.md) |
| Run Windows Crash Doctor | [`../windows-crash-doctor/README.md`](../windows-crash-doctor/README.md) |
| See optional open-source diagnostic providers, licences and supply-chain rules | [`OPEN_SOURCE_INTEGRATIONS.md`](OPEN_SOURCE_INTEGRATIONS.md) |
| Understand the architecture and design rules | [`WINDOWS_CRASH_DOCTOR_PLAN.md`](WINDOWS_CRASH_DOCTOR_PLAN.md) |
| See reusable engineering patterns borrowed from Josh's other GitHub repos | [`GITHUB_BORROW_ROADMAP.md`](GITHUB_BORROW_ROADMAP.md) |
| See the ten comparator tools and research sources | [`COMPARABLE_TOOLS_RESEARCH.md`](COMPARABLE_TOOLS_RESEARCH.md) |
| See the full 100-item product backlog | [`ROADMAP_100.md`](ROADMAP_100.md) |
| Handle diagnostic evidence safely | [`../evidence/README.md`](../evidence/README.md) |
| Understand privacy/security constraints | [`../SECURITY_NOTICE.md`](../SECURITY_NOTICE.md) |
| See the current ProBook investigation state | [`../analysis/STATUS.md`](../analysis/STATUS.md) |
| Follow the controlled ProBook test sequence | [`../analysis/TEST_PLAN.md`](../analysis/TEST_PLAN.md) |

## Documentation authority

When documents disagree, use this order:

1. **Raw/current evidence** and generated collector output.
2. `analysis/STATUS.md` for the current ProBook operational state.
3. `analysis/MASTER_ANALYSIS.md` for detailed case interpretation.
4. `windows-crash-doctor/README.md` for currently shipped Crash Doctor behaviour.
5. `REPOSITORY_AUDIT.md` for current cross-cutting quality, risk, integration and release-readiness findings.
6. `PHASE0_IMPLEMENTATION_2026-09-12.md` for the concrete remediation applied to the audit's release blockers; the Product Gate remains the proof that those changes compose successfully.
7. `WINDOWS_CRASH_DOCTOR_PLAN.md` for architecture and intended design.
8. `GITHUB_BORROW_ROADMAP.md` for planned cross-repository adaptations and implementation sequencing.
9. `ROADMAP_100.md` for the broader unimplemented product backlog.

`PURCHASE_SELLER_AND_EBAY_REVIEW.md` and the public dashboard are consumer-facing summaries. They must remain consistent with the case source of truth above and must not upgrade a hypothesis into a fact.

A roadmap item is not a statement that a feature already exists. An audit finding is not resolved merely because implementation code exists; it should be marked resolved only when the relevant acceptance test/release evidence proves the end-to-end behaviour.

## Case records

The files in `analysis/` are investigation records. They are intentionally not rewritten just to make the product documentation look cleaner; doing so could blur when a conclusion was reached and what evidence supported it. Navigation and current-state corrections belong in `STATUS.md`, while historical reasoning remains traceable in the original analysis documents.

The consolidated cross-chat history under `conversation/` is a safe synthesis rather than a verbatim archive. Similar ProBook-family chats are not merged into this physical-device timeline unless machine identity is established.

## Audit maintenance

`REPOSITORY_AUDIT.md` is the repository-wide engineering quality/risk source of truth. Keep its audit IDs stable. When a finding is materially fixed, mark it resolved with the commit/release and the test that proves resolution rather than deleting the historical finding. Re-run a broad audit before major/minor releases or after significant architecture changes.

## Writing rules for future documentation

- State whether a claim is **observed**, **derived**, **historical/inherited**, or **planned**.
- Never describe a planned feature as implemented.
- Prefer exact commands and file paths over prose-only instructions.
- Keep risky actions explicit and separate from read-only diagnosis.
- Link every public evidence claim to its provenance where practical.
- Treat dump files, ETL traces, EVTX, WER reports and screenshots as potentially sensitive.
- Never publish BitLocker recovery passwords, replacement recovery keys, credentials or unreviewed identifying logs.

- [`NETWORK_DOCTOR.md`](NETWORK_DOCTOR.md) — Network Doctor architecture, diagnostic order, learned cases and safety boundary.
