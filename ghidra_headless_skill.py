# -*- coding: utf-8 -*-
"""
ghidra-headless-skill -- Wrap Ghidra headless analysis as a standard agent skill.

Input: a binary the user owns or is authorized to analyze. Output: a JSON
report (metadata, functions, imports, strings) + decompiler pseudocode paths,
produced by Ghidra's analyzeHeadless via a post-script that emits JSON.

Design: the *skill* layer is fully testable without Ghidra installed --
command construction, report schema validation, and agent-facing summarization
are pure Python; the actual analyzeHeadless invocation is one subprocess call
behind a graceful "Ghidra not available" path. A --demo mode generates a
synthetic report so the full pipeline can be exercised offline.

Ethics: this tool performs no analysis of its own and only automates a
legitimate, publicly documented NSA Ghidra workflow. See README
"Ethics & Legal Boundaries". Only analyze binaries you own or are explicitly
authorized to test.

Pure stdlib. MIT. v0.1.2
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

REPORT_SCHEMA_VERSION = 1
INVENTORY_SCHEMA_VERSION = 1
MAX_PSEUDOCODE_CHARS = 20000  # agent-facing truncation bound
TIER0_MAX_IMPORTS = 20        # budget mode: bounded lists in tier 0
TIER0_MAX_STRINGS = 20
TIER0_MAX_FUNCTIONS = 30
_SAFE_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")


def validate_project_name(name):
    """Project names become directory names and CLI args -- keep them boring."""
    if not _SAFE_NAME.match(name or ""):
        raise ValueError("project name must match [A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
    return name


def build_command(binary_path, project_dir, project_name,
                  ghidra_path="analyzeHeadless", script_path=None,
                  extra_args=None, timeout=600):
    """Build the analyzeHeadless argv. Pure function -- testable without Ghidra.

    The post-script (export_report.py, shipped alongside this skill inside the
    Ghidra script directory) writes report.json + pseudocode fragments using
    Ghidra's public scripting API, following the documented headless workflow
    at https://ghidra-sre.org/ (Ghidra help -> Headless Analyzer).
    """
    if not os.path.isfile(binary_path):
        raise FileNotFoundError("binary not found: %s" % binary_path)
    validate_project_name(project_name)
    os.makedirs(project_dir, exist_ok=True)
    script_path = script_path or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ghidra_scripts", "export_report.py")
    if not os.path.isfile(script_path):
        raise FileNotFoundError("post-script missing: %s" % script_path)
    argv = [ghidra_path, project_dir, project_name,
            "-import", os.path.abspath(binary_path),
            "-postScript", os.path.abspath(script_path),
            "-scriptPath", os.path.dirname(os.path.abspath(script_path)),
            "-deleteProject",
            ]
    argv.extend(extra_args or [])
    return argv


def locate_ghidra():
    """Find analyzeHeadless on PATH or GHIDRA_HEADLESS env var. Returns argv[0] or None."""
    env = os.environ.get("GHIDRA_HEADLESS")
    if env and os.path.isfile(env):
        return env
    return shutil.which("analyzeHeadless")


def run_analysis(binary_path, project_dir=None, project_name="agent_analysis",
                 timeout=600, dry_run=False):
    """Run headless analysis; return (report_dict, meta). Never raises on
    missing Ghidra -- degrades to an explicit 'unavailable' report."""
    project_dir = project_dir or tempfile.mkdtemp(prefix="ghidra_skill_")
    meta = {"started": time.time(), "dry_run": dry_run}
    try:
        argv = build_command(binary_path, project_dir, project_name,
                             ghidra_path=locate_ghidra() or "analyzeHeadless",
                             timeout=timeout)
    except (FileNotFoundError, ValueError) as exc:
        return {"schema_version": REPORT_SCHEMA_VERSION, "status": "error",
                "error": str(exc)}, meta
    meta["argv"] = argv
    if dry_run or locate_ghidra() is None:
        status = "dry_run" if dry_run else "ghidra_not_found"
        return {"schema_version": REPORT_SCHEMA_VERSION, "status": status,
                "command": argv,
                "hint": "install Ghidra and set GHIDRA_HEADLESS to analyzeHeadless"}, meta
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"schema_version": REPORT_SCHEMA_VERSION, "status": "error",
                "error": "analysis timed out after %ss" % timeout}, meta
    meta["returncode"] = proc.returncode
    report_path = os.path.join(os.getcwd(), "report.json")
    if proc.returncode == 0 and os.path.isfile(report_path):
        with open(report_path, "r", encoding="utf-8", errors="replace") as f:
            return parse_report(f.read()), meta
    return {"schema_version": REPORT_SCHEMA_VERSION, "status": "error",
            "error": "analyzeHeadless exited %d" % proc.returncode,
            "stderr_tail": (proc.stderr or "")[-2000:]}, meta


def parse_report(json_text):
    """Validate + normalize a report JSON string. Raises ValueError on schema
    violations so upstream agents get a clear failure, not silent garbage."""
    try:
        data = json.loads(json_text)
    except json.JSONDecodeError as exc:
        raise ValueError("report is not valid JSON: %s" % exc)
    if not isinstance(data, dict):
        raise ValueError("report root must be an object")
    if data.get("schema_version") != REPORT_SCHEMA_VERSION:
        raise ValueError("unsupported schema_version: %r" % data.get("schema_version"))
    for key in ("status", "binary"):
        if key not in data:
            raise ValueError("report missing required key: %s" % key)
    data.setdefault("functions", [])
    data.setdefault("imports", [])
    data.setdefault("strings", [])
    data.setdefault("pseudocode", {})
    if not isinstance(data["functions"], list) or not isinstance(data["pseudocode"], dict):
        raise ValueError("functions must be a list, pseudocode must be an object")
    return data


def summarize_for_agent(report, max_pseudocode_chars=MAX_PSEUDOCODE_CHARS):
    """Compact agent-facing view: cap pseudocode, keep structured metadata."""
    out = dict(report)
    pc = {}
    budget = max_pseudocode_chars
    for name, code in report.get("pseudocode", {}).items():
        if budget <= 0:
            pc[name] = "...truncated (budget exhausted)"
            continue
        piece = code[:budget]
        if len(code) > budget:
            piece += "...truncated"
        budget -= len(piece)
        pc[name] = piece
    out["pseudocode"] = pc
    out["summary"] = {
        "functions": len(report.get("functions", [])),
        "imports": len(report.get("imports", [])),
        "strings": len(report.get("strings", [])),
        "pseudocode_entries": len(report.get("pseudocode", {})),
    }
    return out


# ---------------- batch mode: N binaries -> one merged inventory ----------------

def build_batch_plan(binary_paths, project_dir, project_name_prefix="batch",
                     timeout=600, ghidra_path=None):
    """Plan one headless run per binary. Pure function -- testable without Ghidra.

    Returns a list of {"binary", "project_name", "argv", "timeout"} entries with
    unique per-binary project names (analyzeHeadless locks a project directory,
    so shared names would serialize or collide). Raises ValueError listing every
    missing path so agents fix all inputs in one round-trip.
    """
    ghidra_path = ghidra_path or locate_ghidra() or "analyzeHeadless"
    missing = [p for p in binary_paths if not os.path.isfile(p)]
    if missing:
        raise ValueError("binaries not found: %s" % ", ".join(missing))
    project_dir = os.path.abspath(project_dir)
    os.makedirs(project_dir, exist_ok=True)
    plan = []
    for idx, path in enumerate(binary_paths):
        name = "%s_%03d" % (validate_project_name(project_name_prefix), idx)
        argv = build_command(path, project_dir, name, ghidra_path=ghidra_path,
                             timeout=timeout)
        plan.append({"binary": os.path.abspath(path), "project_name": name,
                     "argv": argv, "timeout": timeout})
    return plan


def run_batch(binary_paths, out_dir, project_name_prefix="batch", timeout=600,
              dry_run=False, ghidra_path=None):
    """Run the batch plan and merge per-binary reports into one inventory.

    Without Ghidra (or with dry_run=True) every entry degrades to an explicit
    dry_run/ghidra_not_found status, and the merge still runs over those
    placeholders so the full pipeline stays exercisable offline. Returns
    (inventory_dict, meta) and writes inventory.json into out_dir.
    """
    plan = build_batch_plan(binary_paths, out_dir,
                            project_name_prefix=project_name_prefix,
                            timeout=timeout, ghidra_path=ghidra_path)
    meta = {"started": time.time(), "dry_run": dry_run, "plan": plan}
    reports = []
    if dry_run:
        for entry in plan:
            reports.append({"schema_version": REPORT_SCHEMA_VERSION,
                            "status": "dry_run", "binary": entry["binary"],
                            "command": entry["argv"]})
    else:
        old_cwd = os.getcwd()
        try:
            os.chdir(out_dir)
            for entry in plan:
                report, _meta = run_analysis(entry["binary"],
                                             project_dir=out_dir,
                                             project_name=entry["project_name"],
                                             timeout=timeout)
                reports.append(report)
        finally:
            os.chdir(old_cwd)
    inventory = merge_reports(reports, dry_run=dry_run)
    inventory_path = os.path.join(out_dir, "inventory.json")
    with open(inventory_path, "w", encoding="utf-8") as f:
        json.dump(inventory, f, indent=1)
    meta["inventory_path"] = inventory_path
    return inventory, meta


def merge_reports(reports, dry_run=False):
    """Merge per-binary reports into one inventory object. Raises ValueError on
    any report that is not schema-valid or not status ok/dry_run -- a batch is
    either fully accounted for or fails loudly, never silently partial."""
    entries = []
    totals = {"functions": 0, "imports": 0, "strings": 0}
    import_sets = []
    for idx, report in enumerate(reports):
        try:
            report = parse_report(json.dumps(report) if not isinstance(report, str)
                                  else report)
        except ValueError as exc:
            raise ValueError("entry %d is not a valid report: %s" % (idx, exc))
        if report.get("status") not in ("ok", "dry_run"):
            raise ValueError("entry %d has status %r -- batch refuses silent "
                             "partials" % (idx, report.get("status")))
        if report.get("status") == "dry_run":
            entries.append({"binary": report.get("binary", "unknown"),
                            "status": "dry_run", "functions": 0,
                            "imports": 0, "strings": 0})
            import_sets.append(set())
            continue
        summary = summarize_for_agent(report)["summary"]
        entries.append({
            "binary": report["binary"], "status": "ok",
            "functions": summary["functions"], "imports": summary["imports"],
            "strings": summary["strings"],
            "format": (report.get("metadata") or {}).get("format"),
        })
        totals["functions"] += summary["functions"]
        totals["imports"] += summary["imports"]
        totals["strings"] += summary["strings"]
        import_sets.append(set(report.get("imports", [])))
    entries.sort(key=lambda e: e["binary"])
    shared = []
    for i in range(len(import_sets)):
        for j in range(i + 1, len(import_sets)):
            for imp in sorted(import_sets[i] & import_sets[j]):
                shared.append({"import": imp, "binaries": [i, j]})
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "kind": "inventory",
        "dry_run": bool(dry_run),
        "binary_count": len(entries),
        "entries": entries,
        "totals": totals,
        "shared_imports": shared,
    }


# ---------------- budget mode: tiered context-window compaction ----------------

def budget_report(report, budget_chars=6000):
    """Split a report into tier0 (bounded overview) + tier1 (pseudocode until
    the budget is spent) + a deferred list. Pure and deterministic: same input
    always yields the same tiers, so an agent can request tier 2
    (full_functions=[...]) reproducibly.

    Unlike summarize_for_agent (single flat truncation), the tiers stay under
    one explicit char budget and report what was left out.
    """
    report = dict(report)
    functions = report.get("functions", [])
    tier0 = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": report.get("status"),
        "binary": report.get("binary"),
        "metadata": report.get("metadata", {}),
        "summary": {
            "functions": len(functions),
            "imports": len(report.get("imports", [])),
            "strings": len(report.get("strings", [])),
            "pseudocode_entries": len(report.get("pseudocode", {})),
        },
        "imports": report.get("imports", [])[:TIER0_MAX_IMPORTS],
        "strings": report.get("strings", [])[:TIER0_MAX_STRINGS],
        "functions": [{"name": f.get("name"), "addr": f.get("addr"),
                       "size": f.get("size")}
                      for f in functions[:TIER0_MAX_FUNCTIONS]],
    }
    tier0_json = json.dumps(tier0, ensure_ascii=False, sort_keys=True)
    used = len(tier0_json)
    pseudocode = report.get("pseudocode", {})
    tier1_pc = {}
    deferred = []
    for name in sorted(pseudocode):  # deterministic order
        code = pseudocode[name]
        allowance = budget_chars - used
        if allowance <= 0:
            deferred.append(name)
            continue
        if len(code) <= allowance:
            tier1_pc[name] = code
        else:
            marker = "...truncated"
            if allowance > len(marker):
                tier1_pc[name] = code[:allowance - len(marker)] + marker
            else:
                tier1_pc[name] = code[:allowance]  # no room for the marker
        used += len(tier1_pc[name])
    deferred = sorted(n for n in pseudocode if n not in tier1_pc)
    return {
        "tier0": tier0,
        "tier0_json": tier0_json,
        "tier1": {"pseudocode": tier1_pc},
        "deferred_functions": deferred,
        "used_chars": used,
        "budget_chars": budget_chars,
        "next": "done" if not deferred else
                "budget_report(..., full_functions=[...])",
    }




def demo_report():
    """Synthetic-but-schema-valid report for offline pipeline testing."""
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "status": "ok",
        "binary": "demo_sample.exe (synthetic)",
        "metadata": {"format": "PE64", "entry": "0x140001000", "size_bytes": 14336},
        "functions": [
            {"name": "entry", "addr": "0x140001000", "size": 42},
            {"name": "check_license", "addr": "0x140001100", "size": 310},
            {"name": "parse_header", "addr": "0x140002000", "size": 128},
        ],
        "imports": ["kernel32.dll!CreateFileW", "kernel32.dll!VirtualAlloc",
                    "advapi32.dll!RegOpenKeyExW"],
        "strings": ["LICENSE-KEY", "C:\\ProgramData\\cfg.bin", "malformed header"],
        "pseudocode": {
            "check_license": ("int check_license(void) {\n"
                              "  long key = RegRead(\"HKLM\\\\License\");\n"
                              "  return (key ^ 0x5A5A) == 0x1234;\n"
                              "}\n"),
        },
    }


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ghidra-headless-skill",
        description="Agent skill: binary -> Ghidra headless -> JSON report + pseudocode.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_a = sub.add_parser("analyze", help="run headless analysis on an owned binary")
    p_a.add_argument("binary")
    p_a.add_argument("--project-dir", default=None)
    p_a.add_argument("--project-name", default="agent_analysis")
    p_a.add_argument("--timeout", type=int, default=600)
    p_a.add_argument("--dry-run", action="store_true",
                     help="print the analyzeHeadless command without running it")

    p_v = sub.add_parser("validate", help="validate a report.json file")
    p_v.add_argument("report")

    p_s = sub.add_parser("summarize", help="compact a report for an agent context window")
    p_s.add_argument("report")
    p_s.add_argument("--max-pc-chars", type=int, default=MAX_PSEUDOCODE_CHARS)

    p_b = sub.add_parser("batch",
                         help="analyze N binaries headlessly, merge into one inventory.json")
    p_b.add_argument("binaries", nargs="+")
    p_b.add_argument("--out-dir", default=None,
                     help="output directory (default: per-run temp dir)")
    p_b.add_argument("--prefix", default="batch", help="project-name prefix")
    p_b.add_argument("--timeout", type=int, default=600)
    p_b.add_argument("--dry-run", action="store_true",
                     help="plan argv per binary and write a dry_run inventory, no Ghidra call")

    p_t = sub.add_parser("budget",
                         help="tier0+tier1 compaction of a report under one char budget")
    p_t.add_argument("report")
    p_t.add_argument("--budget", type=int, default=6000,
                     help="total char budget for tier0+tier1 (default 6000)")

    sub.add_parser("demo", help="generate a synthetic report and run the offline pipeline (~0.1 s)")

    args = ap.parse_args(argv)
    if args.cmd == "analyze":
        report, meta = run_analysis(args.binary, args.project_dir, args.project_name,
                                    timeout=args.timeout, dry_run=args.dry_run)
        print(json.dumps({"report": report, "meta": meta}, indent=2, default=str))
        return 0 if report.get("status") in ("ok", "dry_run") else 2
    if args.cmd == "validate":
        with open(args.report, "r", encoding="utf-8", errors="replace") as f:
            print(json.dumps(parse_report(f.read()), indent=2)[:4000])
        return 0
    if args.cmd == "summarize":
        with open(args.report, "r", encoding="utf-8", errors="replace") as f:
            print(json.dumps(summarize_for_agent(parse_report(f.read()),
                                                 args.max_pc_chars), indent=2))
        return 0
    if args.cmd == "batch":
        out_dir = args.out_dir or tempfile.mkdtemp(prefix="ghidra_batch_")
        try:
            inventory, meta = run_batch(args.binaries, out_dir,
                                        project_name_prefix=args.prefix,
                                        timeout=args.timeout,
                                        dry_run=args.dry_run)
        except ValueError as exc:
            print(json.dumps({"status": "error", "error": str(exc)}, indent=2))
            return 2
        print(json.dumps({"inventory": inventory,
                          "inventory_path": meta["inventory_path"],
                          "dry_run": args.dry_run}, indent=2, default=str))
        return 0
    if args.cmd == "budget":
        with open(args.report, "r", encoding="utf-8", errors="replace") as f:
            bud = budget_report(parse_report(f.read()), budget_chars=args.budget)
        print(json.dumps(bud, indent=2, ensure_ascii=False))
        return 0
    if args.cmd == "demo":
        rep = demo_report()
        text = json.dumps(rep)
        parsed = summarize_for_agent(parse_report(text),
                                     max_pseudocode_chars=10 ** 9)
        print(json.dumps(parsed, indent=2))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
