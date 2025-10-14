# merged_response.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

# Severity order (lower number = higher priority in sorting)
SEV_ORDER: Dict[str, int] = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _safe_list(d: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    """Return a list at d[key] or [] if missing/not a list."""
    v = d.get(key, [])
    return v if isinstance(v, list) else []


def _first(*vals):
    """Return the first truthy value (not None/empty)."""
    for v in vals:
        if v:
            return v
    return None


def _dedupe_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Deduplicate conservatively by (Type, ID, Title, Function, Category, Severity).
    This keeps distinct findings that differ in any of these dimensions.
    """
    seen = set()
    out: List[Dict[str, Any]] = []
    for i in issues:
        key = (
            i.get("Type", ""),
            i.get("ID", ""),
            i.get("Title", ""),
            i.get("Function", ""),
            i.get("Category", ""),
            i.get("Severity", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(i)
    return out


def _sort_issues(issues: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Sort by severity (HIGH→LOW), then Type, then ID, then Title."""
    def key(i: Dict[str, Any]):
        return (
            SEV_ORDER.get(i.get("Severity", ""), 99),
            i.get("Type", "") or "",
            i.get("ID", "") or "",
            i.get("Title", "") or "",
        )
    return sorted(issues, key=key)


def _counters(issues: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate counts by code (ID), severity, and type for quick UI summaries."""
    by_code: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_type: Dict[str, int] = {}

    for i in issues:
        code = i.get("ID")
        sev = i.get("Severity")
        typ = i.get("Type")
        if code:
            by_code[code] = by_code.get(code, 0) + 1
        if sev:
            by_severity[sev] = by_severity.get(sev, 0) + 1
        if typ:
            by_type[typ] = by_type.get(typ, 0) + 1

    return {"by_code": by_code, "by_severity": by_severity, "by_type": by_type}


# --------- Synthetic formatted_info fallbacks (if a module doesn't provide one) ---------

def _synthetic_ac_formatted(ac_resp: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Fallback for Access-Control:
      {
        "functions-no-ac-checks": [ { "name": str, "critical_state_vars": [str,...] }, ... ],
        "functions-weak-ac-checks": [ { "name": str, "critical_state_vars": [str,...] }, ... ]
      }
    Derived from issues_found (parses "(state: ...)" in Function field if present).
    """
    issues = ac_resp.get("issues_found")
    if not isinstance(issues, list) or not issues:
        return None

    no_ac_list: List[Dict[str, Any]] = []
    weak_ac_list: List[Dict[str, Any]] = []

    for it in issues:
        if not isinstance(it, dict):
            continue
        func = it.get("Function") or ""
        state_vars: List[str] = []
        fname_only = func
        if "(state:" in func:
            try:
                fname_only = func.split(" (state:", 1)[0].strip()
                inside = func.split("(state:", 1)[1].split(")", 1)[0]
                state_vars = [s.strip() for s in inside.split(",") if s.strip()]
            except Exception:
                pass

        code = (it.get("ID") or "").upper()
        sev = (it.get("Severity") or "").upper()
        bucket = "functions-weak-ac-checks" if (sev == "MEDIUM" or code == "AC-101") else "functions-no-ac-checks"
        entry = {"name": fname_only, "critical_state_vars": state_vars}

        if bucket == "functions-no-ac-checks":
            no_ac_list.append(entry)
        else:
            weak_ac_list.append(entry)

    return {"functions-no-ac-checks": no_ac_list, "functions-weak-ac-checks": weak_ac_list}


def _synthetic_acm_formatted(acm_resp: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Fallback for Mint-Access-Control:
      {
        "functions-unbounded-admin-mint": [{ "name": str }, ...],
        "functions-public-mint-without-economic-gate": [{ "name": str }, ...],
        "functions-weak-access-control": [{ "name": str }, ...]
      }
    Uses issue IDs MM-001/MM-002/MM-101 to bucket when formatted_info is missing.
    """
    issues = acm_resp.get("issues_found")
    if not isinstance(issues, list) or not issues:
        return None

    buckets = {
        "functions-unbounded-admin-mint": [],
        "functions-public-mint-without-economic-gate": [],
        "functions-weak-access-control": [],
    }

    for it in issues:
        if not isinstance(it, dict):
            continue
        fn = (it.get("Function") or "").split(" (state:")[0]
        code = (it.get("ID") or "").upper()
        if code == "MM-001":
            buckets["functions-unbounded-admin-mint"].append({"name": fn})
        elif code == "MM-002":
            buckets["functions-public-mint-without-economic-gate"].append({"name": fn})
        elif code == "MM-101":
            buckets["functions-weak-access-control"].append({"name": fn})

    # If nothing classified, return None to avoid empty object noise
    if not any(buckets.values()):
        return None
    return buckets


# --------------------------------- MERGE ---------------------------------

def merge_scan_responses(
    resp_iv: Optional[Dict[str, Any]],
    resp_ac: Optional[Dict[str, Any]],
    resp_acm: Optional[Dict[str, Any]],   
    resp_mco: Optional[Dict[str, Any]],   
) -> Dict[str, Any]:
    """
    Merge four module responses (IV + AC + Mint-AC + MCO) into one.

    Inputs (flexible):
      resp_iv: {
        "chain": str, "address": str,
        "issues_found": [ { ID, Type, Category, Title, Severity, Description, Function }, ... ],
        "summary": str,
        "formatted_info": {...}   # IV normalized block
      }

      resp_ac: {
        "chain": str, "address": str,
        "issues_found": [ { ... } ],
        "summary": str,
        "formatted_info": { "functions-no-ac-checks": [...], "functions-weak-ac-checks": [...] }  # or omitted
      }

      resp_acm: {
        "chain": str, "address": str,
        "issues_found": [ { ... } ],
        "summary": str,
        "formatted_info": {
            "functions-unbounded-admin-mint": [...],
            "functions-public-mint-without-economic-gate": [...],
            "functions-weak-access-control": [...]
        }  # or omitted
      }

      resp_mco: {
        "chain": str, "address": str,
        "issues_found": [ { ... } ],
        "summary": str,
        "formatted_info": {
            "vault-core": [...],
            "token-core": [...],
            "upgrade-core": [...],
            "access-role-core": [...],
        }  # or omitted
      }

    Returns:
      {
        "chain": str,
        "address": str,
        "issues_found": [ ...merged, deduped, sorted... ],
        "summary": "N total issue(s) — <iv> | <ac> | <acm>",
        "counts": { "by_code": {...}, "by_severity": {...}, "by_type": {...} },
        "module_summaries": {
            "input_validation": str|None,
            "access_control": str|None,
            "mint_access_control": str|None,
            "missing_critical_overrides": str|None
        },
        "formatted_info": { "IV": {...}|None, "AC": {...}|None, "ACM": {...}|None,  "MCO": {...}|None }
      }
    """
    resp_iv  = resp_iv or {}
    resp_ac  = resp_ac or {}
    resp_acm = resp_acm or {}
    resp_mco = resp_mco or {}


    # Basic metadata
    chain = _first(resp_iv.get("chain"), resp_ac.get("chain"), resp_acm.get("chain"), resp_mco.get("chain"))
    address = _first(resp_iv.get("address"), resp_ac.get("address"), resp_acm.get("address"), resp_mco.get("address"))

    # Merge issues
    iv_issues  = _safe_list(resp_iv, "issues_found")
    ac_issues  = _safe_list(resp_ac, "issues_found")
    acm_issues = _safe_list(resp_acm, "issues_found")
    mco_issues = _safe_list(resp_mco, "issues_found")

    # merged_issues = _dedupe_issues(iv_issues + ac_issues + acm_issues + mco_issues)
    merged_issues = iv_issues + ac_issues + acm_issues + mco_issues

    merged_issues = _sort_issues(merged_issues)

    # Summary
    iv_sum  = resp_iv.get("summary")
    ac_sum  = resp_ac.get("summary")
    acm_sum = resp_acm.get("summary")
    mco_sum = resp_mco.get("summary")

    total = len(merged_issues)
    # parts = [p for p in (iv_sum, ac_sum, acm_sum) if p]
    parts = [str(p).strip().split(')')[0]+')' for p in (iv_sum, ac_sum, acm_sum, mco_sum) if p and str(p).strip()[0]!='0']
    summary = f"{total} total issue(s)" + (f" — {' | '.join(parts)}" if parts else "")

    # Counters for UI
    counts = _counters(merged_issues)

    # Unified formatted_info (keep blocks if provided; otherwise synthesize where possible)
    formatted_info = {
        "IV":  resp_iv.get("formatted_info"),
        "AC":  resp_ac.get("formatted_info")  or _synthetic_ac_formatted(resp_ac),
        "ACM": resp_acm.get("formatted_info") or _synthetic_acm_formatted(resp_acm),
        "MCO": resp_mco.get("formatted_info"),
    }

    return {
        "chain": chain,
        "address": address,
        "issues_found": merged_issues,
        "summary": summary,
        "counts": counts,
        "module_summaries": {
            "input_validation": iv_sum,
            "access_control": ac_sum,
            "mint_access_control": acm_sum,
            "missing_critical_overrides": mco_sum,

        },
        "formatted_info": formatted_info,
    }
