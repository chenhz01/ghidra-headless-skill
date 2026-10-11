# Alignment Audit (Rules 85-100 / 16 items) — ghidra-headless-skill v0.1.2

Audited: 2026-10-11, against ALIGNMENT-16.md. Round 3 (differentiation vs anchors: cellebrite-labs/ghidra-rpc 379★, mrphrazer/ghidra-headless-mcp 188★ — both anchor READMEs deep-read; facts cited in README "How this differs" section).

| # | Check | Status | Evidence |
|---|-------|--------|----------|
| 1 | Safety/Ethics section | PASS | Dedicated "Ethics & Legal Boundaries" section unchanged and intact: authorization requirement, permitted/prohibited uses, jurisdiction reminders, auditable argv trail, no-network guarantee; opening still states only-owned-binaries scope |
| 2 | Privacy (no secrets/real names) | PASS | Re-scanned after v0.1.2 changes: `grep -rInE "(sk-\|ghp_\|api[_-]?key...)"` over *.py/*.md → zero hits; no keys/tokens/real names; no telemetry/network in new code paths (batch/budget are pure local computation) |
| 3 | Copyright boundary | PASS | Anchor comparison uses only README-level facts restated in our own words (daemon/MCP architecture, capability categories); no >50-char contiguous borrowing from either anchor; diff direction explicitly attributed to ghidra-rpc's documented BSim feature; LICENSE (MIT) present |
| 4 | Fact-check annotations | PASS | Wrapper numbers measured (45/45 checks in 1.4 s, demo <0.1 s, batch dry-run <1 s, repro commands given); Ghidra analysis durations remain [estimated]; anchor-star counts and capability claims sourced to anchor READMEs "as of 2026-10-11" |
| 5 | Confidence grading | PASS | High (≥80%) wrapper logic incl. new batch/budget (offline-unit-tested, determinism asserted); Medium (60–79%) end-to-end first run with post-script caveat — both stated in README |
| 6 | Minimal Fallback (PLAN B) | PASS | Demo mode + batch dry-run (`batch ... --dry-run` writes a valid inventory.json with zero Ghidra calls — new offline capability) + dry-run argv preview; three-level fallback intact |
| 7 | Quickstart timing | PASS | "~10 min first run incl. Ghidra download; ~1 min after"; batch/budget commands added with measured offline timings |
| 8 | Design trade-offs / priorities | PASS | Priority order unchanged (auditability first); batch refuses silent partials and budget tier0-is-unconditional behavior documented as consequences in Limits |
| 9 | CHANGELOG ≥2 entries | PASS | v0.1.0 + v0.1.1 + v0.1.2; v0.1.2 names the two new capabilities, the dropped diff idea (honesty call), and the red-green-caused truncation-marker fix |
| 10 | Exemption (session rule 94) | N/A | Session-level rule; static repo content unaffected |
| 11 | Time-sensitive data dated | PASS | "as of 2026-10-11" in Quickstart, Status, and the anchor-comparison section (star counts + capability claims are the time-sensitive data) |
| 12 | Core Assumptions ≥3 | PASS | 4 assumptions retained under [Core Assumptions] |
| 13 | Logic triple (functional/error/edge) | PASS | self_test.py now 5 families / 45 checks, all PASS: A functional, B error paths, C extreme edge (25 legacy checks unchanged and green), D batch (plan shape, unique project names, missing-binary rejection, dry-run inventory, merge totals, shared-import detection, merge rejects bad entries), E budget (tier bounds, budget enforcement incl. truncation-marker regression, deferred list, determinism, CLI smoke) |
| 14 | FAQ "When NOT to use" | PASS | 4 anti-use cases intact; anchor-comparison section adds "use them for deep interactive RE; use this for batch triage" role boundary |
| 15 | ≥2 content iterations | PASS | v0.1.0 → v0.1.1 → v0.1.2; round-3 dimension "differentiation correctness": anchor deep-read → 2 capabilities neither README documents → dropped 1 idea that duplicated ghidra-rpc's documented diff feature; 20 checks added (25→45) |
| 16 | ≤60-word first screen | PASS | Opening paragraph unchanged from v0.1.1 (44 words incl. need-judgment sentence) |

Additional: **Limits & Second-order Effects** extended (rule 16 second-order thinking): batch inventories are counts-not-understanding with import-overlap steering risk; budget tier0 emitted unconditionally even under tiny budgets.

Honesty record (rule 88/87 spirit): the initially planned "function-level diff mode" was **abandoned** after the anchor README read showed ghidra-rpc documents binary diffing with BSim function matching — replaced by the batch/budget directions that neither anchor documents.
