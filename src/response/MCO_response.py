# MCO_response.py

from typing import Any, Dict, List

# Stable codes (no counters)
MCO_CODES = {
    "vault_core": "MCO-001",
    "token": "MCO-002",
    "upgrade": "MCO-003",
    "access_role" : "MCO-004",
}

MCO_LABELS = {
    "MCO-001": "vault-core",
    "MCO-002": "token-core",
    "MCO-003": "upgrade-core",
    "MCO-004": "access-role-core",
}

# Severities per category
MCO_SEVERITY = {
    "MCO-001": "HIGH",
    "MCO-002": "HIGH",
    "MCO-003": "HIGH",
    "MCO-004": "MEDIUM",
}

TYPE_LABEL = "Missing-Critical-Override"   # to align with your other modules' Type field


def _safe_list(v) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return []


def _format_override_info(result: Dict[str, List[str]]) -> Dict[str, Any]:

    vault_core = _safe_list(result.get("vault_core"))
    token = _safe_list(result.get("token"))
    upgrade = _safe_list(result.get("upgrade"))
    access_role = _safe_list(result.get("access_role"))


    return {
        "vault-core": [{"name": fn} for fn in vault_core],
        "token-core": [{"name": fn} for fn in token],
        "upgrade-core": [{"name": fn} for fn in upgrade],
        "access-role-core": [{"name": fn} for fn in access_role],
        "totals": {
            "vault-core": len(vault_core),
            "token-core": len(token),
            "upgrade-core": len(upgrade),
            "access-role-core": len(access_role),  
        },
    }


def _mk_issue(code: str, func: str) -> Dict[str, Any]:
    """Create a single issue record with consistent fields."""
    title = f"{code} — Core function {func} not Overriden and is Exposed"
    category = MCO_LABELS[code]
    severity = MCO_SEVERITY[code]

    t_func = func.split('.')[1].split('(')[0]+'()'  # minimal_func_name for UI


    # Short, precise descriptions tailored by code
    if code == "MCO-001":
        title = f"{code} — Vault Core function `{t_func}` is not Overriden and is exposed"
        desc = (
            f"{func} is a core function of {func.split('.')[0]} Vault Contract and needs to be overriden by the derived contracts\n"
        )
    elif code == "MCO-002":
        title = f"{code} — ERC Token Core function `{t_func}` is not Overriden and is exposed"
        desc = (
            f"{func} is a core function of {func.split('.')[0]} Token contract and needs to be overriden by the derived contracts"
        )
    elif code == "MCO-003":
        title = f"{code} — Upgrade/Proxy Core function `{t_func}` is not Overriden and is exposed"
        desc = (
            f"{func} is a core function of {func.split('.')[0]} contract and needs to be overriden by the derived contracts"
        )
    else: #"MCO-004"
        title = f"{code} — Ownable Core function `{t_func}` is not Overriden and is exposed"
        desc = (
            f"{func} is a core function of {func.split('.')[0]} contract and needs to be overriden by the derived contracts"
        )

    return {
        "ID": code,
        "Type": TYPE_LABEL,
        "Category": category,
        "Title": title,
        "Severity": severity,
        "Description": desc,
        "Function": func,
    }


def build_override_response(
    chain: str,
    address: str,
    result: Dict[str, List[str]],
) -> Dict[str, Any]:
   
    vault_core = _safe_list(result.get("vault_core"))
    token = _safe_list(result.get("token"))
    upgrade = _safe_list(result.get("upgrade"))
    access_role = _safe_list(result.get("access_role"))

    issues: List[Dict[str, Any]] = []

    # MCO-001: 
    for fn in vault_core:
        issues.append(_mk_issue(MCO_CODES["vault_core"], fn))

    # MCO-002: 
    for fn in token:
        issues.append(_mk_issue(MCO_CODES["token"], fn))

    # MCO-101: 
    for fn in upgrade:
        issues.append(_mk_issue(MCO_CODES["upgrade"], fn))
    
    # MCO-101:
    for fn in access_role:
        issues.append(_mk_issue(MCO_CODES["access_role"], fn))

    totals = {
        "vault-core": len(vault_core),
        "token-core": len(token),
        "upgrade-core": len(upgrade),
        "access-role-core": len(access_role),  
    }
    total_issues = sum(totals.values())

    summary = (
        f"{total_issues} Missing Override issue(s): "
        f"{totals['vault-core']} vault-core, "
        f"{totals['token-core']} token-core, "
        f"{totals['upgrade-core']} upgrade-core,"
        f"{totals['access-role-core']} access-role-core,"

    )

    formatted_info = _format_override_info(result)

    return {
        "chain": chain,
        "address": address,
        "issues_found": issues,
        "summary": summary,
        "formatted_info": formatted_info,
    }
