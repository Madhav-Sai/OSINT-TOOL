import os
import time
import streamlit as st
import requests
from typing import Optional, Dict, Any

from utils.helpers import retry_on_failure

VIEWDNS_API_KEY = os.getenv("VIEWDNS_API_KEY")


@retry_on_failure(max_retries=3, delay=1, show_errors=False)
def _vdns_get(endpoint: str, params: dict) -> Optional[Dict[str, Any]]:
    if not VIEWDNS_API_KEY:
        return None
    params["apikey"] = VIEWDNS_API_KEY
    params["output"] = "json"
    r = requests.get(
        f"https://api.viewdns.info/{endpoint}/",
        params=params, timeout=30
    )
    if r.status_code == 401: st.error("❌ ViewDNS: Invalid API key"); return None
    if r.status_code == 429: st.warning("⚠️ ViewDNS: Rate limit exceeded"); return None
    if r.status_code != 200: return None
    return r.json()


def _check_site_status(domain: str):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            start = time.time()
            r = requests.head(url, timeout=10, allow_redirects=True,
                              headers={"User-Agent": "Mozilla/5.0"})
            latency = round((time.time() - start) * 1000)
            if r.status_code < 500:
                return ("up", latency)
            else:
                return ("down", f"HTTP {r.status_code}")
        except requests.exceptions.SSLError:
            continue
        except requests.exceptions.ConnectionError:
            return ("down", "Connection refused / DNS failure")
        except requests.exceptions.Timeout:
            return ("down", "Request timed out (>10 s)")
        except Exception as e:
            return ("uncertain", str(e))
    return ("down", "No response on HTTPS or HTTP")


def render_dns_domain(domain: str):
    st.subheader("DNS Intelligence (ViewDNS)")

    if not VIEWDNS_API_KEY:
        st.warning("⚠️ ViewDNS API key not configured")
        return

    with st.expander("🕐 IP History", expanded=False):
        with st.spinner("Fetching IP history…"):
            data = _vdns_get("iphistory", {"domain": domain})
        if data:
            records = data.get("response", {}).get("records", [])
            if records:
                for rec in records:
                    st.markdown(f"""<div class="card">
                    <b>IP:</b> {rec.get('ip','N/A')} &nbsp;
                    <b>Location:</b> {rec.get('location','N/A')}<br>
                    <b>Owner:</b> {rec.get('owner','N/A')} &nbsp;
                    <b>Last Seen:</b> {rec.get('lastseen','N/A')}
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("ℹ️ No IP history records found")
        else:
            st.warning("⚠️ Could not fetch IP history")

    with st.expander("📋 NS Lookup", expanded=False):
        with st.spinner("Running NS lookup…"):
            data = _vdns_get("dnsrecord", {"domain": domain, "recordtype": "ANY"})
        if data:
            records = data.get("response", {}).get("records", [])
            if records:
                for rec in records:
                    st.markdown(f"""<div class="card">
                    <b>Name:</b> {rec.get('name','N/A')}<br>
                    <b>Type:</b> {rec.get('type','N/A')} &nbsp;
                    <b>TTL:</b> {rec.get('ttl','N/A')}<br>
                    <b>Data:</b> {rec.get('data','N/A')}
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("ℹ️ No DNS records returned")
        else:
            st.warning("⚠️ Could not fetch DNS records")

    with st.expander("Site Status Check", expanded=False):
        with st.spinner("Checking site status…"):
            site_status, site_latency = _check_site_status(domain)
        if site_status == "up":
            st.markdown(
                f'<div class="card" style="border-left-color:#0064B4;">'
                f'<b>Status:</b> <span class="green">✅ Site is UP</span> &nbsp; '
                f'<b>Response:</b> {site_latency} ms</div>',
                unsafe_allow_html=True
            )
        elif site_status == "down":
            st.markdown(
                f'<div class="card" style="border-left-color:#F87171;">'
                f'<b>Status:</b> <span class="red">❌ Site is DOWN</span> &nbsp; '
                f'<b>Reason:</b> {site_latency}</div>',
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                f'<div class="card" style="border-left-color:#FCD34D;">'
                f'<b>Status:</b> <span class="yellow">⚠️ Uncertain</span> &nbsp; '
                f'{site_latency}</div>',
                unsafe_allow_html=True
            )


def render_dns_ip(ip: str):
    st.subheader("DNS Intelligence (ViewDNS)")

    if not VIEWDNS_API_KEY:
        st.warning("⚠️ ViewDNS API key not configured")
        return

    with st.expander("Reverse IP — Domains on this IP", expanded=False):
        with st.spinner("Fetching reverse IP…"):
            data = _vdns_get("reverseip", {"host": ip})
        if data:
            domains_list = data.get("response", {}).get("domains", [])
            if not isinstance(domains_list, list):
                domains_list = [domains_list]
            if domains_list:
                c1, c2 = st.columns(2)
                for i, d in enumerate(domains_list[:20]):
                    col = c1 if i % 2 == 0 else c2
                    name = d.get("name", str(d)) if isinstance(d, dict) else str(d)
                    resolved = d.get("last_resolved", "N/A") if isinstance(d, dict) else "N/A"
                    col.markdown(f"""<div class="card">
                    <b>Domain:</b> {name}<br>
                    <b>Last Resolved:</b> {resolved}
                    </div>""", unsafe_allow_html=True)
                if len(domains_list) > 20:
                    st.info(f"ℹ️ Showing 20 of {len(domains_list)} domains")
            else:
                st.info("ℹ️ No domains found on this IP")
        else:
            st.warning("⚠️ Could not fetch reverse IP data")

    with st.expander("🔌 Port Scan", expanded=False):
        with st.spinner("Running port scan…"):
            data = _vdns_get("portscan", {"host": ip})
        if data:
            port_list = data.get("response", {}).get("port", [])
            if not isinstance(port_list, list):
                port_list = [port_list]
            if port_list:
                open_ports = [p for p in port_list if str(p.get("status", "")).lower() == "open"]
                if open_ports:
                    for p in open_ports:
                        st.markdown(f"""<div class="card">
                        <b>Port:</b> {p.get('number','N/A')} &nbsp;
                        <b>Service:</b> {p.get('service','Unknown')} &nbsp;
                        <b>Status:</b> <span class="green">OPEN</span>
                        </div>""", unsafe_allow_html=True)
                else:
                    for p in port_list:
                        st.markdown(
                            f"<div class='engine'>• Port {p.get('number','?')} – "
                            f"{p.get('service','?')} – {p.get('status','?')}</div>",
                            unsafe_allow_html=True
                        )
            else:
                st.info("ℹ️ No port data returned")
        else:
            st.warning("⚠️ Could not run port scan")
