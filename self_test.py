# -*- coding: utf-8 -*-
"""self_test.py for ghidra-headless-skill.

Three test families (ALIGNMENT-16 rule 97):
  A. functional  -- command build, demo pipeline, parse/summarize, dry-run
  B. error paths -- missing binary, bad project names, corrupt/old-schema
                    reports, missing post-script
  C. extreme edge -- empty binary file, huge report, 10k functions,
                    unicode/binary junk in pseudocode, empty report fields
  D. batch mode  -- multi-binary plan, dry-run batch, inventory merge,
                    shared-import detection, merge rejection of bad reports
  E. budget mode -- tiered token-budget compaction, deterministic output,
                    zero/one budgets, CLI smoke

Run:  python self_test.py
"""
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ghidra_headless_skill as ghs

PASS = 0
FAIL = 0
RESULTS = []


def check(name, cond, info=""):
    global PASS, FAIL
    if cond:
        PASS += 1
    else:
        FAIL += 1
    RESULTS.append("%-4s %s %s" % ("PASS" if cond else "FAIL", name, info))


def section(t):
    RESULTS.append("")
    RESULTS.append("== %s ==" % t)


tmp = tempfile.mkdtemp(prefix="ghs_")
fake_bin = os.path.join(tmp, "sample.bin")
with open(fake_bin, "wb") as f:
    f.write(b"MZ" + b"\x00" * 64)

# ---------- A. functional ----------
section("A. functional")
argv = ghs.build_command(fake_bin, os.path.join(tmp, "proj"), "proj1")
check("command shape", argv[0] == "analyzeHeadless" and "-import" in argv
      and "-postScript" in argv and "-deleteProject" in argv, " ".join(argv[4:6]))

rep = ghs.demo_report()
parsed = ghs.parse_report(json.dumps(rep))
check("demo report parses", parsed["status"] == "ok" and parsed["binary"])
summ = ghs.summarize_for_agent(parsed)
check("summary counts", summ["summary"]["functions"] == 3
      and summ["summary"]["pseudocode_entries"] == 1)

# dry-run path works without Ghidra installed
report, meta = ghs.run_analysis(fake_bin, project_dir=os.path.join(tmp, "p2"),
                                dry_run=True)
check("dry-run returns command", report["status"] == "dry_run"
      and "-import" in report["command"])

# graceful degradation when Ghidra is absent (force by pointing PATH-less)
old = os.environ.pop("GHIDRA_HEADLESS", None)
try:
    report2, meta2 = ghs.run_analysis(fake_bin, project_dir=os.path.join(tmp, "p3"))
    check("missing ghidra degrades cleanly", report2["status"] in ("ghidra_not_found", "error"),
          report2["status"])
finally:
    if old:
        os.environ["GHIDRA_HEADLESS"] = old

# CLI smoke
cli = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                    "ghidra_headless_skill.py")]
p1 = subprocess.run(cli + ["demo"], capture_output=True, text=True)
check("cli demo exit 0 + valid json", p1.returncode == 0
      and json.loads(p1.stdout)["status"] == "ok")
report_file = os.path.join(tmp, "report.json")
with open(report_file, "w", encoding="utf-8") as f:
    f.write(json.dumps(rep))
p2 = subprocess.run(cli + ["summarize", report_file, "--max-pc-chars", "20"],
                    capture_output=True, text=True)
check("cli summarize truncates", p2.returncode == 0
      and "truncated" in p2.stdout)
p3 = subprocess.run(cli + ["analyze", fake_bin, "--dry-run"], capture_output=True, text=True)
check("cli analyze dry-run", p3.returncode == 0 and '"dry_run"' in p3.stdout)

# ---------- B. error paths ----------
section("B. error paths")
try:
    ghs.build_command(os.path.join(tmp, "nope.bin"), tmp, "p")
    check("rejects missing binary", False, "no exception")
except FileNotFoundError:
    check("rejects missing binary", True)

for bad in ["../evil", "a b", "", "x" * 100, "p;rm -rf /", None]:
    try:
        ghs.validate_project_name(bad)
        check("rejects project name %r" % (bad[:12] if bad else bad), False, "accepted")
    except ValueError:
        check("rejects project name %r" % (bad[:12] if bad else bad), True)

for label, text in [("not json", "{oops"), ("root array", "[]"),
                    ("wrong schema", json.dumps({"schema_version": 99, "status": "ok", "binary": "x"})),
                    ("missing key", json.dumps({"schema_version": 1, "status": "ok"}))]:
    try:
        ghs.parse_report(text)
        check("rejects report: %s" % label, False, "accepted")
    except ValueError:
        check("rejects report: %s" % label, True)

try:
    ghs.build_command(fake_bin, tmp, "ok_name",
                      script_path=os.path.join(tmp, "missing_script.py"))
    check("rejects missing post-script", False, "no exception")
except FileNotFoundError:
    check("rejects missing post-script", True)

# ---------- C. extreme edge ----------
section("C. extreme edge")
empty_bin = os.path.join(tmp, "empty.bin")
open(empty_bin, "wb").close()
argv_e = ghs.build_command(empty_bin, tmp, "proj_e")
check("empty binary file builds command", "-import" in argv_e)  # Ghidra would reject format; skill layer tolerates

huge_pc = {"f%d" % i: "x" * 1000 for i in range(50)}
big_rep = dict(rep, pseudocode=huge_pc)
t0 = time.perf_counter()
capped = ghs.summarize_for_agent(big_rep, max_pseudocode_chars=5000)
dt = time.perf_counter() - t0
total = sum(len(v) for v in capped["pseudocode"].values())
check("pseudocode budget enforced", total <= 5000 + 50 * 40 and dt < 1.0,
      "%d chars in %.3fs" % (total, dt))

many_funcs = dict(rep, functions=[{"name": "f%d" % i, "addr": "0x%x" % i, "size": 8}
                                  for i in range(10000)])
check("10k-function report parses", len(ghs.parse_report(
    json.dumps(many_funcs))["functions"]) == 10000)

junk = dict(rep, pseudocode={"weird": "\ufffd\x00\x01 binary junk \xe9"})
summed = ghs.summarize_for_agent(ghs.parse_report(json.dumps(junk)))
check("binary junk tolerated", "weird" in summed["pseudocode"])

empty_rep = {"schema_version": 1, "status": "ok", "binary": "empty.elf"}
norm = ghs.parse_report(json.dumps(empty_rep))
check("empty sections normalized", norm["functions"] == [] and norm["pseudocode"] == {})

# ---------- D. batch mode (multi-binary inventory) ----------
section("D. batch mode")
bin2 = os.path.join(tmp, "sample2.bin")
with open(bin2, "wb") as f:
    f.write(b"MZ" + b"\x01" * 64)

plan = ghs.build_batch_plan([fake_bin, bin2], os.path.join(tmp, "bproj"))
check("batch plan two entries", len(plan) == 2)
check("batch unique project names",
      plan[0]["project_name"] != plan[1]["project_name"])
check("batch argv per binary",
      all("-import" in e["argv"] and e["argv"][4] == os.path.abspath(b)
          for e, b in zip(plan, [fake_bin, bin2])))

try:
    ghs.build_batch_plan([fake_bin, os.path.join(tmp, "ghost.bin")], tmp)
    check("batch rejects missing binary", False, "accepted")
except ValueError:
    check("batch rejects missing binary", True)

# dry-run batch: every entry resolves to a dry_run status without Ghidra
inv_dir = os.path.join(tmp, "bout")
inventory, batch_meta = ghs.run_batch([fake_bin, bin2], inv_dir, dry_run=True)
check("batch dry-run statuses", inventory["dry_run"] is True
      and all(e["status"] == "dry_run" for e in inventory["entries"]))
check("batch meta plan recorded", len(batch_meta["plan"]) == 2
      and os.path.isfile(batch_meta["inventory_path"]))

# merge: two valid reports -> inventory with totals + shared imports
rep2 = dict(rep, binary="sample2.bin",
            imports=["kernel32.dll!CreateFileW", "ws2_32.dll!send"])
inv = ghs.merge_reports([rep, rep2])
check("inventory kind + count", inv["kind"] == "inventory"
      and inv["binary_count"] == 2)
check("inventory totals", inv["totals"]["functions"] == 6
      and inv["totals"]["imports"] == 5)
shared = [s["import"] for s in inv["shared_imports"]]
check("shared import detected", "kernel32.dll!CreateFileW" in shared, str(shared))
check("inventory entries sorted", [e["binary"] for e in inv["entries"]]
      == sorted(e["binary"] for e in inv["entries"]))

for label, bad in [("not a report", {"foo": 1}), ("error status", {"schema_version": 1, "status": "error"})]:
    try:
        ghs.merge_reports([rep, bad])
        check("merge rejects %s" % label, False, "accepted")
    except ValueError:
        check("merge rejects %s" % label, True)

# ---------- E. budget mode (tiered agent context budget) ----------
section("E. budget mode")
big = dict(rep,
           functions=[{"name": "f%d" % i, "addr": "0x%x" % i, "size": 100 - i}
                      for i in range(50)],
           imports=["kernel32.dll!Import%d" % i for i in range(60)],
           strings=["string_%02d" % i for i in range(60)],
           pseudocode={"f%d" % i: "int f%d(void) { return %d; }\n" % (i, i)
                       for i in range(50)})
bud = ghs.budget_report(big, budget_chars=3000)
check("budget tier0 within budget", len(bud["tier0_json"]) <= 3000, str(len(bud["tier0_json"])))
check("budget tier0 bounded lists", len(bud["tier0"]["imports"]) <= 20
      and len(bud["tier0"]["strings"]) <= 20
      and len(bud["tier0"]["functions"]) <= 30)
check("budget tier1 pseudocode capped",
      len(bud["tier1"]["pseudocode"]) > 0 and bud["used_chars"] <= 3000)
check("budget deferred list", len(bud["deferred_functions"]) == 50
      - len(bud["tier1"]["pseudocode"]))
check("budget has next pointer", bud["next"] in ("done", "budget_report(..., full_functions=[...])"))

bud0 = ghs.budget_report(big, budget_chars=0)
check("budget zero -> tier0 only", bud0["tier1"]["pseudocode"] == {}
      and len(bud0["deferred_functions"]) == 50)
check("budget deterministic",
      json.dumps(ghs.budget_report(big, budget_chars=3000), sort_keys=True)
      == json.dumps(bud, sort_keys=True))

p4 = subprocess.run(cli + ["budget", report_file, "--budget", "1500"],
                    capture_output=True, text=True)
check("cli budget smoke", p4.returncode == 0
      and json.loads(p4.stdout)["used_chars"] <= 1500)

# ---------- report ----------
print("\n".join(RESULTS))
print("")
print("ghidra-headless-skill self-test: %d/%d PASS (families A/B/C/D/E)" % (PASS, PASS + FAIL))
print("pipeline(demo): parse+summarize of synthetic report OK | repro: python ghidra_headless_skill.py demo")
sys.exit(0 if FAIL == 0 else 1)
