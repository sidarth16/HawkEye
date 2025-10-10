# detector_response.py

from typing import Any, Dict, List, Tuple

TYPE_LABEL = "Input-Validation-Calls"  # or "Input-Control" if you prefer

# Stable codes per category (no counters)
KIND_CODE = {
    "delegatecall":   "IVC-001",
    "callcode":       "IVC-002",
    "low_level_call": "IVC-003",
    "staticcall":     "IVC-004",
    "external_call":  "IVC-005",
}

KIND_CATEGORY = {
    "delegatecall":   "Dangerous delegatecall without input validation",
    "callcode":       "Dangerous callcode without input validation",
    "low_level_call": "Low-level external call without input validation",
    "external_call":  "External call without explicit input validation",
    "staticcall":     "Staticcall used without explicit input validation",
}

# Severity policy: all unvalidated calls HIGH, except staticcall LOW
KIND_DEFAULT_SEVERITY = {
    "delegatecall":   "HIGH",
    "callcode":       "HIGH",
    "low_level_call": "HIGH",
    "external_call":  "HIGH",
    "staticcall":     "LOW",
}

def _format_info(info: Dict[str, List[List[Any]]]) -> Dict[str, Any]:
    if not isinstance(info, dict):
        return {"functions": [], "totals": {"functions": 0, "variables": 0, "calls": 0}}

    functions_out = []
    total_vars = 0
    total_calls = 0

    for func_name in sorted(info.keys(), key=lambda s: s or ""):
        pairs = info.get(func_name) or []
        variables_out = []

        for pair in pairs:
            if not isinstance(pair, (list, tuple)) or len(pair) != 2:
                continue
            var_name, calls = pair
            var_name = "" if var_name is None else str(var_name)
            if not isinstance(calls, list):
                calls = [] if calls is None else [str(calls)]
            else:
                calls = ["" if c is None else str(c) for c in calls]

            variables_out.append({
                "name": var_name,
                "call_count": len(calls),
                "call_sites": calls,
            })
            total_vars += 1
            total_calls += len(calls)

        variables_out.sort(key=lambda v: (-v["call_count"], v["name"]))
        functions_out.append({
            "name": func_name,
            "variables": variables_out,
            "total_calls": sum(v["call_count"] for v in variables_out),
        })

    # print("functions_out : ", functions_out)
    return {
        "functions": functions_out,
        "totals": {"functions": len(functions_out), "variables": total_vars, "calls": total_calls}
    }

def _classify_call(call: str) -> Dict[str, str]:
    s = (call or "").lower()
    if "delegatecall" in s:
        return {"kind": "delegatecall", "severity": KIND_DEFAULT_SEVERITY["delegatecall"]}
    if "callcode" in s:
        return {"kind": "callcode", "severity": KIND_DEFAULT_SEVERITY["callcode"]}
    if ".call{" in s or ".call(" in s:
        return {"kind": "low_level_call", "severity": KIND_DEFAULT_SEVERITY["low_level_call"]}
    if "staticcall" in s:
        return {"kind": "staticcall", "severity": KIND_DEFAULT_SEVERITY["staticcall"]}
    return {"kind": "external_call", "severity": KIND_DEFAULT_SEVERITY["external_call"]}

def _max_severity(sevs: List[str]) -> str:
    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    if not sevs:
        return "LOW"
    return max(sevs, key=lambda s: order.get(s, 0))

def _describe_issue(func_name: str, var_name: str, calls: List[str]) -> str:
    bullets = "\n".join(f"    •  {c}" for c in calls[:6])
    more = "" if len(calls) <= 6 else f"\n    ... and {len(calls) - 6} more"
    return (
        f"In `{func_name}`, \nvariable `{var_name}` is an user-input value (or) user-input derived value which is used as a call_target address without proper validation.\nThis might lead to dangerous user-controlled target calls.\n\n"
        f"Observed call sites:\n{bullets}{more}\n\n"
        # "Recommendation:\n"
        # "    • Validate user-controlled addresses and call targets (non-zero, allow/deny lists).\n"
        # "    • Avoid delegatecall / raw low-level calls unless strictly necessary.\n"
    )

def build_detector_response(chain: str, address: str, info: Dict[str, List[List[Any]]]) -> Dict[str, Any]:
    """
    Returns:
      {
        "chain", "address",
        "issues_found": [ { ID, Type, Category, Title, Severity, Description, Function } ],
        "summary",
        "formatted_info"
      }
    """
    formatted = _format_info(info)
    issues: List[Dict[str, Any]] = []

    for f in formatted["functions"]:
        func_name = f["name"]
        for v in f["variables"]:
            var_name = v["name"]
            calls = v["call_sites"]
            if not calls:
                continue

            # classify each call
            sevs: List[str] = []
            kinds = set()
            for c in calls:
                meta = _classify_call(c)
                sevs.append(meta["severity"])
                kinds.add(meta["kind"])

            severity = _max_severity(sevs)

            # choose primary kind by risk priority
            priority = ["delegatecall", "callcode", "low_level_call", "staticcall", "external_call"]
            primary_kind = next((k for k in priority if k in kinds), "external_call")

            category = KIND_CATEGORY.get(primary_kind, "Input validation gap")
            iv_code = KIND_CODE.get(primary_kind, "IV-005")  # stable ID per category
            
            minimal_func_name = func_name.split('.')[1].split('(')[0]+'()'
            # minimal_var_name = var_name.split('.')[1].split('(')[0]+'( )' + '.'+ var_name.split('.')[-1]
            minimal_var_name = var_name.split('(')[0]+'()' + '.'+var_name.split('.')[-1]


            title = f"{iv_code} — Missing Input Validation in `{minimal_func_name}` leading to unsafe calls by `{var_name.split('.')[-1]}`"
            description = _describe_issue(func_name, var_name, calls)
            function_field = f"{func_name}"
            var_field = f"{var_name}"
            if var_name:
                issues.append({
                    "ID": iv_code,
                    "Type": TYPE_LABEL,
                    "Category": category,
                    "Title": title,
                    "Severity": severity,
                    "Description": description,
                    "Function": function_field,
                    "Variable" : minimal_var_name
                })
            else:
                issues.append({
                    "ID": iv_code,
                    "Type": TYPE_LABEL,
                    "Category": category,
                    "Title": title,
                    "Severity": severity,
                    "Description": description,
                    "Function": function_field,
                })


    totals = formatted["totals"]
    print(issues)
    print(len(issues))
    summary = (
        f"{len(issues)} input-validation issue(s) across "
        f"{totals['functions']} function(s), {totals['calls']} external call site(s)."
    )
    print(summary)

    return {
        "chain": chain,
        "address": address,
        "issues_found": issues,
        "summary": summary,
        "formatted_info": formatted,
    }
