# ghidra-headless-skill

**Turn any binary you own into a JSON analysis report + pseudocode for your AI agent, in one command.** This wraps Ghidra's documented headless mode as a standard agent skill. You need it if your security-audit or triage agents keep hand-rolling Ghidra invocations.

## Problem

Ghidra ([NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)) is the de-facto open-source reverse-engineering framework: disassembly, decompilation, and a scripting interface, all automatable. Its B-side is underused: the **headless analyzer + post-scripts** are a ready-made backend for AI reverse-engineering agents — more orchestration-friendly and more compatible across binary formats than most alternatives — yet almost nobody has packaged it as a clean agent-facing interface. Agents end up gluing subprocess calls, parsing fragile console output, and re-inventing report schemas per project.

This repo is that missing wrapper: `binary in -> standardized JSON report + truncated pseudocode out`, with a strict schema, graceful degradation when Ghidra is absent, and a demo mode that exercises the whole pipeline offline.

## How it works

1. `build_command` — constructs the `analyzeHeadless` argv (`-import <bin> -postScript export_report.py -deleteProject`), validating paths and project names (defense against shell-adjacent misuse).
2. `ghidra_scripts/export_report.py` — a Ghidra post-script using only the public scripting API (function manager, decompiler interface, external-manager imports, defined-data strings) to write `report.json`. Follows the workflow documented in the Ghidra help ("Headless Analyzer") and at ghidra-sre.org.
3. `parse_report` — schema validation (`schema_version`, required keys, type checks) so agents fail loudly on garbage instead of hallucinating over it.
4. `summarize_for_agent` — compacts the report to a context-window budget (pseudocode truncation, count summaries).
5. `run_analysis` — one subprocess call with timeout; returns `dry_run` or `ghidra_not_found` statuses instead of crashing when Ghidra is not installed.
6. `build_batch_plan` / `run_batch` / `merge_reports` — plan one headless run per binary (unique project names), execute with the same graceful degradation, and merge everything into one schema-checked `inventory.json` with per-binary entries, totals, and shared-import pairs. Batches refuse silent partials: any invalid or failed entry fails the merge loudly.
7. `budget_report` — tiered compaction under one explicit char budget: tier0 (bounded overview: metadata, counts, ≤20 imports/strings, ≤30 functions) + tier1 (pseudocode filled into the remaining budget, truncation markers inside it) + a deterministic `deferred_functions` list for on-demand tier-2 requests.

## Quickstart (~10 min first run incl. Ghidra download; ~1 min after)

```bash
python self_test.py                          # 45 checks, <2 s, no Ghidra needed
python ghidra_headless_skill.py demo         # offline synthetic pipeline, ~0.1 s
# with Ghidra installed:
export GHIDRA_HEADLESS=/path/to/ghidra/support/analyzeHeadless
python ghidra_headless_skill.py analyze ./your_binary --dry-run   # preview argv
python ghidra_headless_skill.py analyze ./your_binary             # full run
python ghidra_headless_skill.py summarize report.json --max-pc-chars 8000
python ghidra_headless_skill.py batch ./bin1 ./bin2 ./bin3 --out-dir ./inv      # corpus -> inventory.json
python ghidra_headless_skill.py batch ./bin1 ./bin2 --dry-run                   # preview per-binary argv, no Ghidra call
python ghidra_headless_skill.py budget report.json --budget 6000                # tier0+tier1 under one char budget
```

Measured (repro: `python self_test.py`; Python 3.12, Windows, as of 2026-10-11): 45/45 checks pass; demo pipeline (parse + schema validation + agent summarization) completes in <0.1 s; batch dry-run over 2 binaries writes a valid inventory.json in <1 s. Actual `analyzeHeadless` runtime depends entirely on binary size and Ghidra — a 100 KB PE typically analyzes in 1–3 min [estimated; varies by binary and hardware]. Confidence: **High (≥80%)** for the wrapper logic — it is fully unit-tested offline. Confidence **Medium (60–79%)** for first-run experience end-to-end — the post-script targets current stable Ghidra public APIs, but Ghidra's scripting API evolves between releases [unverified across all versions].

## Ethics & Legal Boundaries

- **Only analyze binaries you own, have written, or are explicitly and lawfully authorized to test** (your own software, purchased software where local analysis is permitted, or engagement-scoped samples under a contract/CTF ruleset).
- This tool is for **defensive security research, malware triage you are authorized to perform, interoperability, education, and audit**. It adds no capability Ghidra does not already have; it only automates a documented workflow.
- **Not for**: attacking systems you do not own, circumventing license enforcement, exfiltrating third-party code, or any unlawful reverse engineering. You are responsible for compliance with your jurisdiction's laws (e.g., DMCA anti-circumvention, computer-misuse statutes, export controls) and with Ghidra's own usage terms.
- The wrapper intentionally records its full command argv in every report meta block, keeping agent-driven analysis **auditable** — every action traces back to an explicit, reviewable command.
- No telemetry, no network calls, no samples leave your machine.

## How this differs from ghidra-rpc (and headless-mcp)

The "Ghidra for agents" category already has strong repos — [cellebrite-labs/ghidra-rpc](https://github.com/cellebrite-labs/ghidra-rpc) (379★) and [mrphrazer/ghidra-headless-mcp](https://github.com/mrphrazer/ghidra-headless-mcp) (188★). This skill is a different tool for a different job, not a competitor. Facts from their READMEs (as of 2026-10-11):

- **ghidra-rpc** runs Ghidra as a *persistent background daemon* (PyGhidra in-process) with a CLI returning JSON: decompile/disassemble/CFG inspection, caller/callee navigation, symbol renaming and annotation, type recovery, patching via SLEIGH, and **version diffing of two builds with BSim function matching**. It is session-oriented: you load binaries into a warm project and mutate them over time.
- **ghidra-headless-mcp** is an *MCP server* (stdio/TCP) with 212 tools over a live pyghidra backend: program lifecycle, transactions with undo/redo, scripting access, read-only-by-default mutation workflows.

What both are, per their READMEs: **stateful, interactive, one-program-at-a-time bridges** — the right choice when an agent works one binary deeply across many turns.

What neither README describes, and what this skill adds:

| Capability | Here | Anchor-README fact |
|---|---|---|
| **Batch corpus mode** (`batch`): N binaries → per-binary headless run → one merged, schema-checked `inventory.json` (per-binary function/import/string counts, totals, shared-import pairs) | v0.1.2, `build_batch_plan`/`run_batch`/`merge_reports` | ghidra-rpc README shows single-binary `load` commands only; headless-mcp README shows single-program `program.open` lifecycle only. Neither mentions multi-binary batch runs or a merged inventory artifact |
| **Tiered token-budget mode** (`budget`): tier0 bounded overview + tier1 pseudocode filled to one explicit char budget + deterministic deferred list the agent can request in full | v0.1.2, `budget_report` | ghidra-rpc README mentions no context-budget handling; headless-mcp paginates its *tool catalog* (`tools/list` offset/limit), not analysis output |

What we deliberately do **not** do (their territory): live sessions, symbol mutation, type recovery, patching, BSim-based function diffing. `ghidra-rpc` already does binary diffing well — we do not duplicate it. Conversely, neither anchor is built for unattended *fire-and-forget* corpus triage with per-run audit trails and zero persistent state (`-deleteProject` every run). Use them for deep interactive RE; use this for batch triage and schema-stable report pipelines.


## Why not X?

| Alternative | Why this still wins |
|---|---|
| Raw `analyzeHeadless` calls from the agent | Works, but every agent project re-implements argv building, output parsing, and timeouts; this standardizes the report schema and fails loudly on corruption |
| radare2 / r2pipe, Binary Ninja | Capable alternatives, but Ghidra's decompiler is free with no license tiers, and its headless + script combo is the most battle-tested for unattended batch analysis; r2 JSON output is verbose and version-unstable for this purpose |
| IDA Pro automation | Excellent decompiler, but proprietary licensing makes it a non-starter for shared agent infrastructure |
| Online sandboxes / SaaS disassemblers | Upload-based: sample leaves your perimeter; this runs fully local, air-gap friendly |
| objdump / strings ad-hoc parsing | Metadata only, no decompilation, no function graph; fine as a first look, weak as an agent backend |

## Minimal Fallback (PLAN B)

No Ghidra installed? Run `python ghidra_headless_skill.py demo` to see the exact report shape your agents will consume, and build against `parse_report`/`summarize_for_agent` — both work on any JSON you point them at. No Ghidra and no Python? The report schema (in this README + `demo` output) is plain JSON: any tool that can emit `functions/imports/strings/pseudocode` keys can fake the backend until you install Ghidra. Worst case, the `--dry-run` flag still emits the exact command your pipeline would run, so ops can execute it manually.

## Design Trade-offs

Priority order on conflict: **auditability > correctness (loud schema failures) > offline testability > speed > report richness.** Consequences: (1) every run records the argv it used; (2) `parse_report` rejects rather than best-effort-parses malformed reports; (3) the skill layer is 100% testable without Ghidra, at the cost of duplicating the report contract between wrapper and post-script; (4) `-deleteProject` is always passed — no persistent Ghidra projects, trading re-analysis speed for zero state accumulation.

## Limits & Second-order Effects

- **The post-script is the compatibility surface.** Ghidra API changes between releases can break `export_report.py`; the wrapper will surface this as an `error` status, not silent garbage. Pseudocode quality is bounded by Ghidra's decompiler, not this tool.
- **Truncation is lossy.** `summarize_for_agent` caps pseudocode; an agent reasoning over truncated code may misjudge a function. Second-order effect: audit teams might accept agent conclusions derived from truncated views — always keep the full `report.json` as the record of truth and treat summaries as navigation, not evidence.
- **Automation amplifies volume.** Cheap, fast binary triage invites bulk analysis; second-order risks include alert fatigue from auto-generated low-context reports and over-trusting decompiler output (decompiled pseudocode is a reconstruction, not source).
- **Timeout defaults (600 s) are arbitrary.** Large or packed binaries need more; packed/obfuscated samples may also need dedicated unpacking before Ghidra sees real code.
- **Batch inventories are counts, not understanding.** `inventory.json` tells you how many functions/imports each binary has and which imports they share — a triage index, not an analysis. Ordering binaries by import overlap to pick "interesting" samples can steer agents away from actually-relevant targets that happen to import nothing unusual.
- **Budget tier0 is emitted unconditionally** — even if it alone exceeds a tiny `--budget`, tier1 then gets nothing. The budget governs what is controllable (tier1 + deferral), not the minimum viable overview.

## FAQ

**Q: Does this include or modify Ghidra?**
A: No. It orchestrates an unmodified Ghidra install and ships one post-script using its public scripting API, per the documented headless workflow.

**Q: Why JSON instead of Ghidra's native project output?**
A: Agents need one predictable, schema-checked, diffable format. Native projects are directories of opaque state; JSON fits context windows and CI logs.

**Q: When NOT to use this?**
A: (Socratic check.) Do **not** use it when (1) you are not authorized to analyze the binary — full stop; (2) you need dynamic analysis (execution traces, unpacking-by-run) — Ghidra headless is static; (3) you need interactive reverse engineering — use Ghidra's GUI, this wrapper throws away the human-in-the-loop strengths; (4) your target is a script/blob without loadable format — Ghidra adds little over `strings` there.

**Q: What does the agent actually receive?**
A: One JSON object: `schema_version, status, binary, metadata, functions[], imports[], strings[], pseudocode{}`, plus `summary` counts and truncated pseudocode after `summarize_for_agent`.

## [Core Assumptions]

1. The operator has lawful authorization for every binary analyzed; the tool enforces nothing at runtime and relies on the audit trail + this document.
2. Ghidra's public headless CLI and scripting API remain stable enough across releases for `-import` / `-postScript` / function-manager / decompiler-interface calls; breakage surfaces as explicit errors.
3. Report consumers are agents or pipelines that treat schema validation failures as fatal (loud-failure design), not as partial data to guess around.
4. Sub-100 KB to low-MB binaries are the primary workload; the 600 s default timeout and truncation budgets assume that scale.

---
Topics: `ghidra` `reverse-engineering` `static-analysis` `ai-agents` `security-research` `decompiler` `malware-triage` `skill`

Status: v0.1.2. Wrapper: pure stdlib, MIT, © zhengming contributors. Ghidra itself is Apache-2.0 by NSA and is **not** included or redistributed. Wrapper numbers as of 2026-10-11, reproducible via `python self_test.py`.

Inspired by the headless/scripting architecture of NationalSecurityAgency/ghidra (https://github.com/NationalSecurityAgency/ghidra); only public documentation concepts are referenced — no Ghidra source text is reproduced here.
