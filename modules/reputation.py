import os
import time
import streamlit as st
import requests
from datetime import datetime, timezone
from typing import Optional

from utils.helpers import retry_on_failure, render_vt_reputation, render_threat_score_block, compute_threat_score

VT_API_KEY        = os.getenv("VT_API_KEY")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


@retry_on_failure(max_retries=3, delay=1)
def fetch_vt_domain(domain):
    if not VT_API_KEY:
        st.warning("⚠️ VirusTotal API key not configured")
        return None
    r = requests.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": VT_API_KEY}, timeout=15
    )
    if r.status_code == 401: st.error("❌ VirusTotal: Invalid API key"); return None
    if r.status_code == 429: st.warning("⚠️ VirusTotal: Rate limit exceeded"); return None
    if r.status_code != 200: raise requests.exceptions.RequestException(f"Status {r.status_code}")
    return r.json()


@retry_on_failure(max_retries=3, delay=1)
def fetch_vt_ip(ip):
    if not VT_API_KEY:
        st.warning("⚠️ VirusTotal API key not configured")
        return None
    r = requests.get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={"x-apikey": VT_API_KEY}, timeout=15
    )
    if r.status_code == 401: st.error("❌ VirusTotal: Invalid API key"); return None
    if r.status_code == 429: st.warning("⚠️ VirusTotal: Rate limit exceeded"); return None
    if r.status_code != 200: raise requests.exceptions.RequestException(f"Status {r.status_code}")
    return r.json()


@retry_on_failure(max_retries=3, delay=1)
def fetch_shodan_ip(ip):
    if not SHODAN_API_KEY:
        st.warning("⚠️ Shodan API key not configured")
        return None
    r = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": SHODAN_API_KEY}, timeout=15
    )
    if r.status_code == 401: st.error("❌ Shodan: Invalid API key"); return None
    if r.status_code == 404: st.info("ℹ️ Shodan: No info for this IP"); return None
    if r.status_code == 429: st.warning("⚠️ Shodan: Rate limit exceeded"); return None
    if r.status_code != 200: raise requests.exceptions.RequestException(f"Status {r.status_code}")
    return r.json()


@retry_on_failure(max_retries=3, delay=1)
def fetch_abuseipdb(ip):
    if not ABUSEIPDB_API_KEY:
        st.warning("⚠️ AbuseIPDB API key not configured")
        return None
    r = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=15
    )
    if r.status_code == 401: st.error("❌ AbuseIPDB: Invalid API key"); return None
    if r.status_code == 429: st.warning("⚠️ AbuseIPDB: Rate limit exceeded"); return None
    if r.status_code != 200: raise requests.exceptions.RequestException(f"Status {r.status_code}")
    return r.json()


def render_ip_reputation(ip: str):
    st.subheader("IP / Domain Reputation")

    vt, sh, ab = None, None, None

    with st.spinner("Fetching VirusTotal data…"):
        vt = fetch_vt_ip(ip)
    if vt and "data" in vt:
        st.markdown("#### VirusTotal Analysis")
        render_vt_reputation(vt["data"]["attributes"])

    if SHODAN_API_KEY:
        with st.spinner("Fetching Shodan data…"):
            sh = fetch_shodan_ip(ip)
        if sh and "error" not in sh:
            st.markdown("#### Shodan Intelligence")
            c1, c2 = st.columns(2)
            c1.markdown(f"""<div class="card">
            <b>Country:</b> {sh.get("country_name","N/A")}<br>
            <b>City:</b>    {sh.get("city","N/A")}<br>
            <b>ISP:</b>     {sh.get("isp","N/A")}
            </div>""", unsafe_allow_html=True)
            c2.markdown(f"""<div class="card">
            <b>Organization:</b> {sh.get("org","N/A")}<br>
            <b>OS:</b>           {sh.get("os","N/A")}<br>
            <b>Open Ports:</b>   {", ".join(map(str, sh.get("ports",[]))) or "None"}
            </div>""", unsafe_allow_html=True)

    if ABUSEIPDB_API_KEY:
        with st.spinner("Fetching AbuseIPDB data…"):
            ab = fetch_abuseipdb(ip)
        if ab and "data" in ab:
            d = ab["data"]
            conf = d.get("abuseConfidenceScore", 0)
            st.markdown("#### ⚠️ AbuseIPDB Reputation")
            c1, c2, c3 = st.columns(3)
            c1.metric("Abuse Confidence", f"{conf}%")
            c2.metric("Total Reports",    d.get("totalReports", 0))
            c3.metric("Distinct Users",   d.get("numDistinctUsers", 0))
            if conf > 75:
                st.error("HIGH RISK — high abuse confidence score!")
            elif conf > 25:
                st.warning("⚠️ MODERATE RISK – reported for abuse")

    threat = compute_threat_score(vt_data=vt, abuse_data=ab, shodan_data=sh)
    render_threat_score_block(threat)


def render_domain_reputation(domain: str):
    st.subheader("IP / Domain Reputation")
    with st.spinner("Fetching VirusTotal data…"):
        vt = fetch_vt_domain(domain)
    if vt and "data" in vt:
        st.markdown("#### VirusTotal Domain Analysis")
        render_vt_reputation(vt["data"]["attributes"])
