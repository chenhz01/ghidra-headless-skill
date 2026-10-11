# Ghidra post-script: export a JSON report + decompiled pseudocode.
# Runs inside analyzeHeadless (-postScript). Uses only Ghidra's public
# scripting API, following the workflow documented in the Ghidra help
# ("Headless Analyzer") and the ghidra-sre.org documentation.
# Jython (Python 2.7 syntax) as required by Ghidra script manager.
# @category: Agents.Export
import json
import os

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


def _func_info(func):
    body = func.getBody()
    return {
        "name": func.getName(),
        "addr": str(func.getEntryPoint()),
        "size": int(body.getNumAddresses()),
    }


def run():
    program = getCurrentProgram()
    fm = program.getFunctionManager()

    functions = [_func_info(f) for f in fm.getFunctions(True)]

    imports = []
    for ext_loc in program.getExternalManager().getExternalLocations():
        imports.append("%s!%s" % (ext_loc.getLibraryName(),
                                  ext_loc.getLabel()))

    strings = []
    listing = program.getListing()
    di = DecompInterface()
    di.openProgram(program)
    monitor = ConsoleTaskMonitor()

    pseudocode = {}
    for f in fm.getFunctions(True):
        try:
            res = di.decompileFunction(f, 30, monitor)
            if res.decompileCompleted():
                pseudocode[f.getName()] = str(res.getDecompiledFunction().getC())
        except Exception:
            pass

    for data in listing.getDefinedData(True):
        dt = data.getDataType().getName().lower()
        if "string" in dt or "unicode" in dt:
            val = data.getValue()
            if val is not None:
                s = str(val)
                if 4 <= len(s) <= 120:
                    strings.append(s)

    report = {
        "schema_version": 1,
        "status": "ok",
        "binary": str(program.getName()),
        "metadata": {
            "format": str(program.getExecutableFormat()),
            "size_bytes": int(program.getExecutableLength()),
        },
        "functions": functions,
        "imports": imports,
        "strings": strings[:500],
        "pseudocode": pseudocode,
    }

    out = os.path.join(os.getcwd(), "report.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=1)
    print("report written: %s" % out)
