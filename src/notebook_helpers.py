import os
from dotenv import load_dotenv

from slither.slither import Slither

from src.detectors import IVC, AC, ACM, MCO
from src.response.IVC_response import build_detector_response
from src.response.AC_response import build_access_control_response
from src.response.ACM_response import build_mint_access_response
from src.response.MCO_response import build_override_response

from src.response.merge_response import merge_scan_responses


from collections import OrderedDict
from IPython.display import display, Markdown

load_dotenv()
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY")



def detect_vulns(chain: str, address: str) -> dict:

    prefix=''
    if chain=="arbitrum": prefix = 'arbi:'
    if chain=="base": prefix = 'base:'
    if chain=='optimism': prefix = 'optim:'

    try:
        sl = Slither(prefix + address, etherscan_api_key=ETHERSCAN_API_KEY)
    except Exception as e :
        print(e)
        raise(e)

    info_IV = IVC.run(sl)
    info_AC = AC.run(sl)
    info_ACM = ACM.run(sl)
    info_MCO = MCO.run(sl)

    response_IV = build_detector_response(chain, address, info_IV)
    response_AC = build_access_control_response(chain, address, info_AC )
    response_ACM = build_mint_access_response(chain, address, info_ACM)
    response_MCO = build_override_response(chain, address, info_MCO)

    merged_response = merge_scan_responses(response_IV, response_AC, response_ACM, response_MCO)
    return merged_response




def _safe_get(i, *keys, default=""):
    for k in keys:
        if isinstance(i, dict) and k in i and i[k] not in (None, ""):
            return i[k]
    return default

def _short_func_label(full_sig):
    """Return Contract.func() short label from full signature."""
    if not full_sig: 
        return ""
    try:
        # contract.func(args)  -> contract.func()
        parts = full_sig.split('.')
        if len(parts) > 1:
            contract = parts[0]
            func = parts[1].split('(')[0]
            return f"{contract}.{func}()"
        return full_sig.split('(')[0] + "()"
    except Exception:
        return full_sig

def _add_markdown_in_description(desc, fname, var):
    """Return a small list of code-like lines from description (heuristic)."""
    desc_lines = desc.split('\n')
    upd_lines = []
    for line in desc_lines : 
        words = line.split()
        upd_words = []
        for word in words : 
            word = word.strip()
            # print('word_befre : ', word)
            if '`' not in word and (fname in word  ):
                word = f"`{word}`"
            upd_words.append(word)
            # print('word_after : ', word)
        upd_lines.append(' '.join(upd_words))
    return '<br/>'.join(upd_lines)

def pretty_print(response):
    """
    Minimal descriptive pretty print for detector response.
    - response: merged response dict (or dict containing issues_found / issues)
    - max_code_lines: how many code-like lines to show per issue (default 6)
    """
    if not response:
        display(Markdown("**No response**"))
        return

    # tolerant extraction of issues
    issues = response.get("issues_found")

    if not issues:
        display(Markdown("✅ **No issues found**"))
        return

    # Normalize entries and group by Type|Category
    groups = OrderedDict()  # key -> list of issues
    for raw in issues:
        Type = _safe_get(raw, "Type", "type") or "Unknown-Type"
        Category = _safe_get(raw, "Category", "category") or "General"
        key = f"{Type} | {Category}"
        groups.setdefault(key, []).append(raw)

    # Header (chain/address if present)
    chain = response.get("chain") or ""
    addr = response.get("address") or ""
    head = f"🔍 0xDetector — {chain}  { ('| ' + addr) if addr else ''}"
    display(Markdown(f"**{head}**\n"))

    # For each group, print header and entries
    out_lines = []
    for gkey, items in groups.items():
        # Group header
        out_lines.append(f"- **{gkey}**")

        seen_funcs = set()
        # For each issue in group
        for it in items:
            ID = _safe_get(it, "ID", "id") or ""
            title = _safe_get(it, "Title", "title") or ""
            full_func = _safe_get(it, "Function", "function", "fn") or ""
            var = _safe_get(it, "Variable", "variable") or ""
            desc = _safe_get(it, "Description", "description") or ""

            short_fn = _short_func_label(full_func)
            # Avoid repeating same function lines
            func_key = (short_fn, full_func, var)
            if func_key in seen_funcs:
                continue
            seen_funcs.add(func_key)

            # First-level: function+optional title (compact)
            if title:
                out_lines.append(f"    - **{title}**")
            else:
                out_lines.append(f"    - {short_fn}")

            # Second-level: full signature + variable
            if full_func:
                # show trimmed full signature on its own indented line
                out_lines.append(f"        - `{full_func}`{('  —  `'+var+'`') if var else ''}")
            elif var:
                out_lines.append(f"        - `variable: {var}`")

            # Third-level: code-like lines extracted from description (indented, bulleted)
            upd_desc = _add_markdown_in_description(desc, full_func, var)
            out_lines.append("            -   " + upd_desc + "")
            
        out_lines.append("<br/><br/>")  # blank line after group


    # Render as Markdown block (preserve indentation)
    md = "\n".join(out_lines)
    display(Markdown(md))

    # Footer summary minimal
    total = len(issues)
    display(Markdown(f"**Total issues:** {total}"))
