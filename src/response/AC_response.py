from typing import Any, Dict, List, Set, Tuple

ADMIN_FUNC_KEYWORDS = {
    "root": ["update", "set", "remove"],
    "merkle": ["update", "set", "remove"],
    "hash": ["update", "set", "remove"],
    "secret": ["update", "set", "remove"],
    "config": ["update", "set", "remove"],
    "router": ["update", "set", "remove"],
    "oracle": ["update", "set", "remove"],
    "owner": ["set", "update", "transfer", "remove", "renounce"],
    "admin": ["set", "update", "transfer", "remove", "renounce"],
    "role": ["set", "update", "remove", "renounce"],

    "implementation": ["update", "set", "remove"],
    "upgrade": ["to"],
    
    "executeOperation": [""],
    "callFunction": [""],
    "flashloan": ["on", "receive", "3156", "execute"],
}

CODE_LABELS = {
    "AC-001": "Unrestricted Admin/Governance Update",
    "AC-002": "Unrestricted Upgrade/Init",
    "AC-003": "Unrestricted Flashloan/Callback entrypoint",
    "AC-101": "Weak validation",
}


def _detect_ac_code(func: str, state_vars: Set[str]) -> str:
    """Detect which AC-* code applies based on keywords."""
    text = func.lower() + " " + " ".join(v.lower() for v in state_vars)
    for kw in ["upgrade", "implementation"]:
        if kw in text:
            return "AC-002"
    for kw in ["executeoperation", "callfunction", "flashloan"]:
        if kw in text:
            return "AC-003"
    for kw in ["admin", "owner", "role", "config", "router", "oracle", "root", "merkle", "hash", "secret"]:
        if kw in text:
            return "AC-001"
    return "AC-001"


def _format_ac_info(ac_result: Dict[str, List[Tuple[Set[str], str]]]) -> Dict[str, Any]:
    """
    Convert AC results into the desired structured format:
    {
      "functions-no-ac-checks": [
        { "name": "FuncName", "state_vars": [ ... ] },
        ...
      ],
      "functions-weak-ac-checks": [
        { "name": "FuncName", "state_vars": [ ... ] },
        ...
      ]
    }
    """
    formatted: Dict[str, List[Dict[str, Any]]] = {
        "functions-no-ac-checks": [],
        "functions-weak-ac-checks": []
    }

    no_ac = ac_result.get("no_AC_checks", []) or []
    weak_ac = ac_result.get("weak_AC_checks", []) or []

    # --- Format "no access control" functions ---
    for state_vars, func in no_ac:
        entry = {
            "name": func,
            "critical_state_vars": sorted(list(state_vars)) if state_vars else []
        }
        formatted["functions-no-ac-checks"].append(entry)

    # --- Format "weak access control" functions ---
    for state_vars, func in weak_ac:
        entry = {
            "name": func,
            "critical_state_vars": sorted(list(state_vars)) if state_vars else []
        }
        formatted["functions-weak-ac-checks"].append(entry)

    return formatted


def build_access_control_response(
    chain: str,
    address: str,
    ac_result: Dict[str, List[Tuple[Set[str], str]]]
) -> Dict[str, Any]:
    """
    Build a user-friendly access control report with formatted_info.
    """
    no_ac = ac_result.get("no_AC_checks", []) or []
    weak_ac = ac_result.get("weak_AC_checks", []) or []
    issues: List[Dict[str, Any]] = []

   

    # --- High severity: no access control ---
    for state_vars, func in no_ac:
        code = _detect_ac_code(func, state_vars)
        sv = ", ".join(sorted(state_vars)) if state_vars else ""
        
        minimal_func_name = func.split('.')[1].split('(')[0]+'(...)'
        minimal_state_vars = [i.split('.')[-2].split('(')[0]+'( )' + '.'+ i.split('.')[-1] for i in state_vars]
        minimal_sv = ", ".join(sorted(minimal_state_vars)) if minimal_state_vars else ""


        desc = f"{func} modifies critical state {f'({sv})' or ''} without proper access control checks."
        if code == "AC-001":
            desc = f"{func} modifies critical admin/governance state {f'({sv})' or ''} without proper access control checks."
        elif code == "AC-002":
            desc = f"{func} calls contract Init / Upgrade without proper access control checks."
        elif code == "AC-003":
            desc = f"{func} executes unvalidated Flashloan Callbacks without proper access control checks."
        if minimal_sv:
            issues.append({
                "ID": code,
                "Type": "Access-Control",
                "Category": CODE_LABELS[code],
                "Title": f"{code} — Unprotected access to `{minimal_func_name}`",
                "Severity": "HIGH",
                "Description": desc,
                "Function": f"{func}", 
                "Variable" : f"{minimal_sv}"
            })
        else:
            issues.append({
            "ID": code,
            "Type": "Access-Control",
            "Category": CODE_LABELS[code],
            "Title": f"{code} — Unprotected access to `{minimal_func_name}`",
            "Severity": "HIGH",
            "Description": desc,
            "Function": f"{func}"
        })

    # --- Medium severity: weak access control ---
    for state_vars, func in weak_ac:
        sv = ", ".join(sorted(state_vars)) if state_vars else ""

        minimal_func_name = func.split('.')[1].split('(')[0]+'(...)'
       

        if sv:
            issues.append({
            "ID": "AC-101",
            "Type": "Access-Control",
            "Category": CODE_LABELS["AC-101"],
            "Title": f"AC-101 — Weak access control in `{minimal_func_name}`",
            "Severity": "MEDIUM",
            "Description": f"{func} uses weak access control validation (e.g., tx.origin, trivial sender checks like '!=').",
            "Function": f"{func}", 
            "Variable" : f"{sv}"
        })
        else:
            issues.append({
                "ID": "AC-101",
                "Type": "Access-Control",
                "Category": CODE_LABELS["AC-101"],
                "Title": f"AC-101 — Weak access control in `{minimal_func_name}`",
                "Severity": "MEDIUM",
                "Description": f"{func} uses weak access control validation (e.g., tx.origin, trivial sender checks).",
                "Function": f"{func}"
            })

    summary = f"{len(issues)} access-control issue(s): {len(no_ac)} unprotected, {len(weak_ac)} weak."

    formatted_info = _format_ac_info(ac_result)

    return {
        "chain": chain,
        "address": address,
        "issues_found": issues,
        "summary": summary,
        "formatted_info": formatted_info
    }
