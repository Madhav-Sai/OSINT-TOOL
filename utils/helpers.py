import re
import time
import math
import functools
import streamlit as st
import requests
from urllib.parse import urlparse
from typing import Optional, Dict, Any


# ──────────────────────────────────────────
# CSS Loader
# ──────────────────────────────────────────
import streamlit as st

def load_css(path: str):
    with open(path, "rb") as f:
        css = f.read().decode("utf-8", errors="ignore")
    st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)

# ──────────────────────────────────────────
# Retry decorator
# ──────────────────────────────────────────
def retry_on_failure(max_retries=3, delay=2, backoff=2, show_errors=True):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            retries, cur = 0, delay
            while retries < max_retries:
                try:
                    return func(*args, **kwargs)
                except (requests.exceptions.Timeout,
                        requests.exceptions.ConnectionError,
                        requests.exceptions.RequestException) as e:
                    retries += 1
                    if retries >= max_retries:
                        if show_errors:
                            st.error(f"⚠️ Request failed – {e}")
                        return None
                    time.sleep(cur)
                    cur *= backoff
                except Exception as e:
                    if show_errors:
                        st.error(f"⚠️ Unexpected error – {e}")
                    return None
            return None
        return wrapper
    return decorator


# ──────────────────────────────────────────
# Input detection
# ──────────────────────────────────────────
def detect_input_type(value: str) -> str:
    value = value.strip()
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", value):
        if all(0 <= int(p) <= 255 for p in value.split(".")):
            return "IP"
    if re.fullmatch(r"[\w\.\-\+]+@[\w\.\-]+\.\w{2,}", value):
        return "EMAIL"
    if value.startswith(("http://", "https://", "ftp://", "www.")):
        try:
            v = ("http://" + value) if value.startswith("www.") else value
            parsed = urlparse(v)
            domain = (parsed.netloc or parsed.path.split("/")[0]).split(":")[0]
            if domain.startswith("www."):
                domain = domain[4:]
            if domain:
                return f"DOMAIN:{domain}"
        except Exception:
            pass
    if re.fullmatch(r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}", value):
        return "DOMAIN"
    if re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.\-]{0,31}", value):
        return "USERNAME"
    return "UNKNOWN"


# ──────────────────────────────────────────
# Threat Scoring
# ──────────────────────────────────────────
def compute_threat_score(vt_data=None, abuse_data=None, shodan_data=None) -> dict:
    sub_scores, weights_used = {}, {}

    if vt_data and "data" in vt_data:
        attrs = vt_data["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values())
        if total > 0:
            raw = (malicious + 0.5 * suspicious) / total
            vt_score = min(100, round(raw * 100 * 2.5))
            sub_scores["VirusTotal"] = vt_score
            weights_used["VirusTotal"] = 0.50

    if abuse_data and "data" in abuse_data:
        conf = abuse_data["data"].get("abuseConfidenceScore", 0)
        sub_scores["AbuseIPDB"] = int(conf)
        weights_used["AbuseIPDB"] = 0.35

    if shodan_data and "error" not in shodan_data:
        n = len(shodan_data.get("ports", []))
        port_score = min(100, round(math.log1p(n) / math.log1p(50) * 100)) if n > 0 else 0
        sub_scores["Shodan"] = port_score
        weights_used["Shodan"] = 0.15

    if not sub_scores:
        return {"score": 0, "level": "Unknown", "color": "", "breakdown": {}, "confidence": "None"}

    total_weight = sum(weights_used.values())
    score = round(sum(
        sub_scores[src] * (weights_used[src] / total_weight)
        for src in sub_scores
    ))

    if score >= 75:
        level, color = "Critical", "red"
    elif score >= 50:
        level, color = "High", "red"
    elif score >= 25:
        level, color = "Medium", "yellow"
    else:
        level, color = "Low", "green"

    n_sources = len(sub_scores)
    confidence = "High" if n_sources == 3 else ("Medium" if n_sources == 2 else "Low")

    return {
        "score": score,
        "level": level,
        "color": color,
        "breakdown": sub_scores,
        "confidence": confidence,
    }


# ──────────────────────────────────────────
# Shared renderer helpers
# ──────────────────────────────────────────
def render_vt_reputation(attrs: dict):
    stats = attrs.get("last_analysis_stats", {})
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Malicious",  stats.get("malicious",  0))
    c2.metric("Suspicious", stats.get("suspicious", 0))
    c3.metric("Harmless",   stats.get("harmless",   0))
    c4.metric("Undetected", stats.get("undetected", 0))

    mal, sus = [], []
    for vendor, res in attrs.get("last_analysis_results", {}).items():
        cat = res.get("category")
        if cat == "malicious":
            mal.append(vendor)
        elif cat == "suspicious":
            sus.append(vendor)

    if mal:
        st.markdown("#### 🚨 Flagged as Malicious by:")
        st.markdown(
            f'<div class="card" style="border-left-color:#F87171;">{", ".join(mal)}</div>',
            unsafe_allow_html=True
        )
    if sus:
        st.markdown("#### ⚠️ Flagged as Suspicious by:")
        st.markdown(
            f'<div class="card" style="border-left-color:#FCD34D;">{", ".join(sus)}</div>',
            unsafe_allow_html=True
        )


def render_threat_score_block(threat: dict):
    st.markdown("### 🎯 Unified Threat Score")
    cols = st.columns([1, 2, 1])
    with cols[0]:
        st.metric("Threat Score", f"{threat['score']} / 100")
    with cols[1]:
        breakdown_html = "".join(
            f"<span class='engine'>• {src}: {sc}/100</span><br>"
            for src, sc in threat["breakdown"].items()
        )
        st.markdown(
            f"<div class='card'>"
            f"<b>Risk Level:</b> <span class='{threat['color']}'>{threat['level']}</span><br>"
            f"<b>Confidence:</b> {threat['confidence']} ({len(threat['breakdown'])} of 3 sources)<br><br>"
            f"{breakdown_html}</div>",
            unsafe_allow_html=True
        )
    with cols[2]:
        lvl = threat["level"]
        if lvl == "Critical":
            st.error("🚨 Critical risk")
        elif lvl == "High":
            st.error("🔴 High risk")
        elif lvl == "Medium":
            st.warning("🟡 Medium risk")
        else:
            st.success("🟢 Low risk")
