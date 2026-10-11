# Changelog

## v0.1.2 — 2026-10-11 (differentiation round vs ghidra-rpc / ghidra-headless-mcp)

Deep-read both anchor READMEs (cellebrite-labs/ghidra-rpc 379★, mrphrazer/ghidra-headless-mcp 188★) and built the two capabilities neither documents. Deliberately dropped the "function-level diff" idea: ghidra-rpc's README documents binary version diffing with BSim function matching, so that direction was already taken — no duplication claimed.

- **Batch corpus mode** (`build_batch_plan` / `run_batch` / `merge_reports` + CLI `batch`): plan one analyzeHeadless run per binary with unique project names; merge per-binary reports into one schema-checked `inventory.json` (per-binary counts, totals, shared-import pairs). Merge refuses silent partials — any invalid/failed entry raises. Full dry-run path works offline without Ghidra.
- **Tiered token-budget mode** (`budget_report` + CLI `budget`): tier0 bounded overview + tier1 pseudocode filled to one explicit char budget + deterministic `deferred_functions` list for on-demand tier-2 requests. Determinism is tested (same input → byte-identical output). Fix caught during red-green: the `...truncated` marker was appended after the budget cut, pushing `used_chars` past the budget; markers now carved out of the allowance.
- **README:** new "How this differs from ghidra-rpc (and headless-mcp)" section with README-sourced facts on both anchors and what is deliberately not duplicated; Limits gained batch-inventory and budget-tier0 caveats.
- **Tests:** 25 → 45 checks (new families D batch / E budget: plan shape, unique project names, missing-binary rejection, dry-run inventory, merge totals, shared-import detection, merge rejection of bad entries, tier bounds, budget enforcement, determinism, CLI smoke).

## v0.1.1 — 2026-10-11 (self-audit revision, round 2)

Iterated against ALIGNMENT-16 (rules 85-100). Changes:

- **Correctness (round-2 fix, caught by CLI smoke test):** `demo` subcommand passed a wrong keyword (`max_pc_chars` vs `max_pseudocode_chars`) and crashed; fixed, 25/25 PASS.
- **Hardening (round-2 additions):** project-name validation now rejects path traversal and shell metacharacters (`../evil`, `p;rm -rf /`) — caught by new error-path tests; `-deleteProject` always passed so agent-driven runs leave no persistent state; every run records its full argv in the report meta block for auditability.
- **Ethics & Legal Boundaries section rewritten** from a placeholder into a concrete policy: authorization requirement, permitted/prohibited uses, jurisdiction reminders, auditable-command rationale, no-network guarantee.
- **README completeness:** added Minimal Fallback (demo-mode backend faking + dry-run ops path), Design Trade-offs priority order (auditability first), Limits & Second-order Effects (truncated-pseudocode over-trust risk, automation volume risk), FAQ with "When NOT to use" (4 cases incl. the authorization stop-rule), 4 [Core Assumptions], two explicit confidence ratings, first-run timing estimate with [estimated]/[unverified] tags.
- **Honest numbers:** wrapper-side numbers are measured (25/25 checks, <2 s); Ghidra-side analysis durations tagged [estimated]/[unverified] since Ghidra is not bundled.

## v0.1.0 — 2026-10-11 (initial draft)

- `build_command`: analyzeHeadless argv construction with path/project validation.
- `run_analysis`: subprocess invocation with timeout, dry-run mode, and graceful `ghidra_not_found` degradation.
- `ghidra_scripts/export_report.py`: post-script (public Ghidra scripting API) exporting JSON report + decompiled pseudocode.
- `parse_report` / `summarize_for_agent`: schema validation and context-budget compaction.
- CLI (`analyze`, `validate`, `summarize`, `demo`) + self_test with functional, error-path, extreme-edge families (21 checks at draft time).
