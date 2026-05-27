import json
import subprocess
import itertools
import streamlit as st
from typing import Dict, Any, List


# ── Pure-Python typo generator (no external tool needed) ──────────────────────
COMMON_TLDS = [".com", ".net", ".org", ".info", ".co", ".io", ".biz"]

def _python_typos(domain: str) -> List[str]:
    """Generate typo variants without any subprocess."""
    if "." not in domain:
        return []
    parts   = domain.rsplit(".", 1)
    name    = parts[0]
    tld     = "." + parts[1]
    results = set()

    # Character omission
    for i in range(len(name)):
        v = name[:i] + name[i+1:]
        if v:
            results.add(v + tld)

    # Character duplication
    for i in range(len(name)):
        results.add(name[:i] + name[i]*2 + name[i+1:] + tld)

    # Adjacent transposition
    for i in range(len(name) - 1):
        v = list(name)
        v[i], v[i+1] = v[i+1], v[i]
        results.add("".join(v) + tld)

    # Common keyboard substitutions
    adjacent = {
        "a": "sq", "b": "vghn", "c": "xdfv", "d": "xcesfr",
        "e": "wrsdf", "f": "dcgvr", "g": "ftyhbv", "h": "gyjnb",
        "i": "ujklo", "j": "hukni", "k": "jilmo", "l": "kiop",
        "m": "njk",  "n": "bhjm",  "o": "iklp",  "p": "ol",
        "q": "wa",   "r": "edft",  "s": "azxdew","t": "rfgy",
        "u": "yhji", "v": "cfgb",  "w": "qase",  "x": "zsdc",
        "y": "tghu", "z": "asx",
    }
    for i, ch in enumerate(name):
        for sub in adjacent.get(ch, ""):
            results.add(name[:i] + sub + name[i+1:] + tld)

    # Hyphen insertion
    for i in range(1, len(name)):
        results.add(name[:i] + "-" + name[i:] + tld)

    # TLD swap
    for alt_tld in COMMON_TLDS:
        if alt_tld != tld:
            results.add(name + alt_tld)

    # Remove the original domain itself
    results.discard(domain)
    return sorted(results)


def _dnstwist_fast(domain: str, timeout: int = 45) -> List[Dict[str, Any]]:
    """Run dnstwist WITHOUT --registered for speed (pure generation only)."""
    try:
        result = subprocess.run(
            ["dnstwist", "--format", "json", domain],
            capture_output=True, text=True, timeout=timeout
        )
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, FileNotFoundError,
            json.JSONDecodeError, Exception):
        pass
    return []


def render_typosquatting(domain: str, limit):
    st.subheader("Typosquatting Analysis")

    with st.spinner("Generating typo domains…"):
        dnstwist_results = _dnstwist_fast(domain)

    if dnstwist_results:
        # dnstwist succeeded — show all variants (no live DNS, just generation)
        lim = len(dnstwist_results) if limit == "All" else limit
        st.markdown(
            f"<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
            f"border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
            f"color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>"
            f"✅ Generated {len(dnstwist_results)} typo variants</div>",
            unsafe_allow_html=True
        )
        for d in dnstwist_results[:lim]:
            fuzzer = d.get("fuzzer", "unknown")
            dom    = d.get("domain", "")
            dns_a  = d.get("dns_a", [])
            dns_str = ", ".join(dns_a) if isinstance(dns_a, list) and dns_a else ""
            label   = f"• {dom} ({fuzzer})" + (f" → {dns_str}" if dns_str else "")
            st.markdown(f"<div class='engine'>{label}</div>",
                        unsafe_allow_html=True)
        if len(dnstwist_results) > lim:
            st.info(f"ℹ️ Showing {lim} of {len(dnstwist_results)} variants")
    else:
        # Fallback: pure Python generation
        typos = _python_typos(domain)
        lim   = len(typos) if limit == "All" else limit
        if typos:
            st.markdown(
                f"<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
                f"border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
                f"color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>"
                f"✅ Generated {len(typos)} typo variants (built-in engine)</div>",
                unsafe_allow_html=True
            )
            for t in typos[:lim]:
                st.markdown(f"<div class='engine'>• {t}</div>",
                            unsafe_allow_html=True)
            if len(typos) > lim:
                st.info(f"ℹ️ Showing {lim} of {len(typos)} variants")
        else:
            st.markdown(
                "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
                "border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
                "color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>"
                "ℹ️ No typo variants could be generated for this domain.</div>",
                unsafe_allow_html=True
            )
