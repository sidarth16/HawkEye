# mint_ac_response.py

from typing import Any, Dict, List

# Stable codes (no counters)
MINT_CODES = {
    "unbounded_admin_mint": "ACM-001",
    "public_mint_without_economic_gate": "ACM-002",
    "weak_access_control": "ACM-101",
}

MINT_LABELS = {
    "ACM-001": "Unbounded admin mint ",
    "ACM-002": "Public mint without economic gate ",
    "ACM-101": "Weak access control",
}

# Severities per category
MINT_SEVERITY = {
    "ACM-001": "HIGH",
    "ACM-002": "HIGH",
    "ACM-101": "MEDIUM",
}

TYPE_LABEL = "Access-Control-Mint"   # to align with your other modules' Type field


def _safe_list(v) -> List[str]:
    if isinstance(v, list):
        return [str(x) for x in v if x]
    return []


def _format_mint_info(mint_result: Dict[str, List[str]]) -> Dict[str, Any]:
    """
    Produce a neat, UI-friendly formatted_info block:

    {
      "functions-unbounded-admin-mint": [ { "name": "Fn" }, ... ],
      "functions-public-mint-without-economic-gate": [ { "name": "Fn" }, ... ],
      "functions-weak-access-control": [ { "name": "Fn" }, ... ],
      "totals": { "unbounded_admin_mint": N1, "public_mint_without_economic_gate": N2, "weak_access_control": N3 }
    }
    """
    unbounded = _safe_list(mint_result.get("unbounded_admin_mint"))
    public_no_gate = _safe_list(mint_result.get("public_mint_without_economic_gate"))
    weak = _safe_list(mint_result.get("weak_access_control"))

    return {
        "functions-unbounded-admin-mint": [{"name": fn} for fn in unbounded],
        "functions-public-mint-without-economic-gate": [{"name": fn} for fn in public_no_gate],
        "functions-weak-access-control": [{"name": fn} for fn in weak],
        "totals": {
            "unbounded_admin_mint": len(unbounded),
            "public_mint_without_economic_gate": len(public_no_gate),
            "weak_access_control": len(weak),
        },
    }


def _mk_issue(code: str, func: str) -> Dict[str, Any]:
    """Create a single issue record with consistent fields."""

    minimal_func_name = func.split('.')[1].split('(')[0]+'(...)'

    title = f"{code} — {MINT_LABELS[code]} in `{minimal_func_name}`"
    category = MINT_LABELS[code]
    severity = MINT_SEVERITY[code]

    # Short, precise descriptions tailored by code
    if code == "ACM-001":
        desc = (
            f"{func} allows privileged/admin minting without sufficient governance guardrails "
            f"(e.g., multi-sig, timelock, or explicit caps). "
            f"This can enable large or repeated mints if the admin key is compromised or misused."
        )
    elif code == "ACM-002":
        desc = (
            f"{func} exposes a public mint path without an economic gate/backing deposit. "
            f"For vault/receipt tokens, ensure previewMint/previewDeposit align and assets are enforced. "
            f"Un-gated mints can inflate supply out of thin air."
        )
    else:  # ACM-101
        desc = (
            f"{func} uses weak or insufficient access control for minting. "
            f"Ensure strong role checks (e.g., onlyRole(MINTER_ROLE)), and avoid weak patterns like tx.origin or trivial sender checks."
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


def build_mint_access_response(
    chain: str,
    address: str,
    mint_result: Dict[str, List[str]],
) -> Dict[str, Any]:
    """
    Build a user-friendly report for the Mint-Access detector.

    Input (example):
      {
        "unbounded_admin_mint": ["MyToken.ownerMintTokens(uint256)"],
        "public_mint_without_economic_gate": [],
        "weak_access_control": []
      }

    Output:
      {
        "chain": "...",
        "address": "...",
        "issues_found": [ { ID, Type, Category, Title, Severity, Description, Function }, ... ],
        "summary": "…",
        "formatted_info": {
          "functions-unbounded-admin-mint": [{ "name": "..." }, ...],
          "functions-public-mint-without-economic-gate": [{ "name": "..." }, ...],
          "functions-weak-access-control": [{ "name": "..." }, ...],
          "totals": {...}
        }
      }
    """
    unbounded = _safe_list(mint_result.get("unbounded_admin_mint"))
    public_no_gate = _safe_list(mint_result.get("public_mint_without_economic_gate"))
    weak = _safe_list(mint_result.get("weak_access_control"))

    issues: List[Dict[str, Any]] = []

    # ACM-001: Unbounded admin mint
    for fn in unbounded:
        issues.append(_mk_issue(MINT_CODES["unbounded_admin_mint"], fn))

    # ACM-002: Public mint without economic gate
    for fn in public_no_gate:
        issues.append(_mk_issue(MINT_CODES["public_mint_without_economic_gate"], fn))

    # ACM-101: Weak access control
    for fn in weak:
        issues.append(_mk_issue(MINT_CODES["weak_access_control"], fn))

    totals = {
        "unbounded_admin_mint": len(unbounded),
        "public_mint_without_economic_gate": len(public_no_gate),
        "weak_access_control": len(weak),
    }
    total_issues = sum(totals.values())

    summary = (
        f"{total_issues} mint access issue(s): "
        f"{totals['unbounded_admin_mint']} unbounded-admin, "
        f"{totals['public_mint_without_economic_gate']} public-no-gate, "
        f"{totals['weak_access_control']} weak-access-control."
    )

    formatted_info = _format_mint_info(mint_result)

    return {
        "chain": chain,
        "address": address,
        "issues_found": issues,
        "summary": summary,
        "formatted_info": formatted_info,
    }
