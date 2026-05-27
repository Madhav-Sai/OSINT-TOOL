"""
network_graph.py — Interactive relationship graph for the OSINT platform.

Builds a pyvis network showing:
  Domain ──► Subdomain(s)
  Domain ──► Resolved IP(s)
  IP     ──► Open Port(s)
  IP     ──► Geolocation tag
  Domain ──► Threat tag  (if VT malicious > 0)
  IP     ──► Threat tag  (if AbuseIPDB > 0)

Falls back gracefully when APIs are unavailable or return no data.
"""

import os
import socket
import requests
import streamlit as st
import streamlit.components.v1 as components
from typing import Optional

from modules.subdomains import fetch_subdomains

VT_API_KEY        = os.getenv("VT_API_KEY")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")


# ── colour palette (matches project theme) ────────────────────────────────────
COLOURS = {
    "target":   {"bg": "#0064B4", "border": "#003C8C", "font": "#ffffff"},  # blue  – root node
    "subdomain":{"bg": "#E8F0FB", "border": "#0064B4", "font": "#0D3380"},  # light blue
    "ip":       {"bg": "#FFF4E6", "border": "#E87B00", "font": "#7A4000"},  # orange
    "port":     {"bg": "#F5F8FF", "border": "#9AAFC8", "font": "#0D3380"},  # grey-blue
    "threat":   {"bg": "#FDECEA", "border": "#C0392B", "font": "#7B1A14"},  # red
    "clean":    {"bg": "#EAF5F0", "border": "#1A7A52", "font": "#0F4A31"},  # green
    "geo":      {"bg": "#F5F0FF", "border": "#7B68EE", "font": "#3B2B8C"},  # purple
}

SHAPES = {
    "target":    "star",
    "subdomain": "dot",
    "ip":        "diamond",
    "port":      "square",
    "threat":    "triangleDown",
    "clean":     "triangle",
    "geo":       "ellipse",
}


def _node(net, nid: str, label: str, kind: str, title: str = ""):
    c = COLOURS[kind]
    net.add_node(
        nid,
        label=label,
        title=title or label,
        shape=SHAPES[kind],
        color={"background": c["bg"], "border": c["border"],
               "highlight": {"background": c["bg"], "border": "#E87B00"}},
        font={"color": c["font"], "size": 13},
        size=38 if kind == "target" else 22 if kind in ("ip", "subdomain") else 15,
    )


def _edge(net, src: str, dst: str, label: str = "", dashes: bool = False):
    net.add_edge(src, dst, label=label,
                 color={"color": "#9AAFC8", "highlight": "#E87B00"},
                 dashes=dashes, width=1.5,
                 font={"size": 10, "color": "#4A6A8A"})


def _resolve_ip(domain: str) -> Optional[str]:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def _vt_domain_ips(domain: str):
    """Return (resolved_ips[], malicious_count) from VirusTotal."""
    if not VT_API_KEY:
        return [], 0
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": VT_API_KEY}, timeout=12
        )
        if r.status_code == 200:
            attrs = r.json()["data"]["attributes"]
            mal = attrs.get("last_analysis_stats", {}).get("malicious", 0)
            # resolutions list gives historical IPs
            ips = []
            for res in attrs.get("last_dns_records", []):
                if res.get("type") in ("A", "AAAA"):
                    ips.append(res["value"])
            return list(set(ips))[:5], mal
    except Exception:
        pass
    return [], 0


def _shodan_ports(ip: str):
    """Return (ports[], country, org) from Shodan."""
    if not SHODAN_API_KEY:
        return [], "", ""
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{ip}",
            params={"key": SHODAN_API_KEY}, timeout=12
        )
        if r.status_code == 200:
            d = r.json()
            return (d.get("ports", [])[:6],
                    d.get("country_name", ""),
                    d.get("org", ""))
    except Exception:
        pass
    return [], "", ""


def _abuseipdb_score(ip: str) -> int:
    if not ABUSEIPDB_API_KEY:
        return -1
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90}, timeout=10
        )
        if r.status_code == 200:
            return r.json()["data"].get("abuseConfidenceScore", 0)
    except Exception:
        pass
    return -1


def build_graph(domain: str, include_subdomains: bool,
                include_ports: bool, include_threat: bool) -> str:
    """Build pyvis network and return the full HTML string."""
    try:
        from pyvis.network import Network
    except ImportError:
        return "<p style='color:red'>pyvis not installed. Run: pip install pyvis</p>"

    net = Network(
        height="600px", width="100%",
        bgcolor="#EEF4FB", font_color="#0D3380",
        directed=True,
    )
    net.set_options("""
    {
      "physics": {
        "enabled": true,
        "solver": "forceAtlas2Based",
        "forceAtlas2Based": {
          "gravitationalConstant": -80,
          "centralGravity": 0.01,
          "springLength": 140,
          "springConstant": 0.06,
          "damping": 0.4
        },
        "stabilization": {"iterations": 200, "fit": true}
      },
      "interaction": {
        "hover": true,
        "tooltipDelay": 100,
        "navigationButtons": true,
        "keyboard": true,
        "zoomView": true
      },
      "edges": {
        "smooth": {"type": "curvedCW", "roundness": 0.15},
        "arrows": {"to": {"enabled": true, "scaleFactor": 0.5}},
        "color": {"color": "#9AAFC8", "highlight": "#E87B00", "hover": "#E87B00"},
        "width": 1.5,
        "selectionWidth": 2.5
      },
      "nodes": {
        "borderWidth": 2,
        "borderWidthSelected": 3,
        "shadow": {"enabled": true, "color": "rgba(0,60,140,0.10)", "size": 6, "x": 2, "y": 2}
      }
    }
    """)

    # ── Root node ─────────────────────────────────────────────────────────────
    _node(net, domain, domain, "target", f"Root target: {domain}")

    # ── VT: resolved IPs + threat ─────────────────────────────────────────────
    vt_ips, vt_mal = _vt_domain_ips(domain)

    # Fallback: plain DNS if VT gave nothing
    if not vt_ips:
        dns_ip = _resolve_ip(domain)
        if dns_ip:
            vt_ips = [dns_ip]

    ip_nodes_added = set()

    for ip in vt_ips:
        if ip in ip_nodes_added:
            continue
        ip_nodes_added.add(ip)
        _node(net, ip, ip, "ip", f"Resolved IP: {ip}")
        _edge(net, domain, ip, "resolves to")

        if include_ports and SHODAN_API_KEY:
            ports, country, org = _shodan_ports(ip)
            if country or org:
                geo_id = f"geo_{ip}"
                geo_label = f"📍 {country}" + (f"\n{org}" if org else "")
                _node(net, geo_id, geo_label, "geo",
                      f"Location: {country}  |  Org: {org}")
                _edge(net, ip, geo_id, "located")
            for port in ports:
                port_id = f"{ip}:{port}"
                _node(net, port_id, f":{port}", "port",
                      f"Open port {port} on {ip}")
                _edge(net, ip, port_id, "open port", dashes=True)

        if include_threat:
            score = _abuseipdb_score(ip)
            if score > 0:
                kind = "threat" if score > 25 else "clean"
                tag_id = f"abuse_{ip}"
                label = f"⚠ Abuse\n{score}%" if kind == "threat" else f"✓ Clean\n{score}%"
                _node(net, tag_id, label, kind,
                      f"AbuseIPDB confidence: {score}%")
                _edge(net, ip, tag_id)

    # ── VT domain threat tag ──────────────────────────────────────────────────
    if include_threat and VT_API_KEY:
        if vt_mal > 0:
            threat_id = f"vt_threat_{domain}"
            _node(net, threat_id, f"⚠ Malicious\n{vt_mal} engines",
                  "threat", f"VirusTotal: {vt_mal} engines flagged this domain")
            _edge(net, domain, threat_id, "flagged by VT")
        elif vt_mal == 0 and vt_ips:
            clean_id = f"vt_clean_{domain}"
            _node(net, clean_id, "✓ VT Clean", "clean",
                  "VirusTotal: no engines flagged this domain")
            _edge(net, domain, clean_id)

    # ── Subdomains ────────────────────────────────────────────────────────────
    if include_subdomains:
        subs = fetch_subdomains(domain)
        shown = 0
        for sub in subs:
            if sub == domain or shown >= 20:
                break
            _node(net, sub, sub, "subdomain", f"Subdomain: {sub}")
            _edge(net, domain, sub, "subdomain")
            # Try to resolve subdomain IP
            sub_ip = _resolve_ip(sub)
            if sub_ip and sub_ip not in ip_nodes_added:
                ip_nodes_added.add(sub_ip)
                _node(net, sub_ip, sub_ip, "ip", f"IP for {sub}")
                _edge(net, sub, sub_ip, "resolves to")
            elif sub_ip and sub_ip in ip_nodes_added:
                _edge(net, sub, sub_ip, "resolves to")
            shown += 1

    # Return HTML string
    return net.generate_html()


def render_network_graph(domain: str):
    st.subheader("🕸 Network Relationship Graph")

    st.markdown(
        "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;"
        "border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;"
        "color:#0D3380;font-size:0.92rem;margin-bottom:12px;'>"
        "Interactive graph — drag nodes, scroll to zoom, hover for details."
        "</div>",
        unsafe_allow_html=True
    )

    # Read toggle values set before search
    include_subdomains = st.session_state.get("ng_subs", True)
    include_ports      = st.session_state.get("ng_ports", True)
    include_threat     = st.session_state.get("ng_threat", True)

    with st.spinner("Building network graph…"):
        html = build_graph(domain, include_subdomains,
                           include_ports, include_threat)

    # Legend
    st.markdown("""
    <div style='display:flex;flex-wrap:wrap;gap:10px;margin:8px 0 12px;font-size:0.8rem;'>
      <span style='background:#0064B4;color:#fff;padding:3px 10px;border-radius:12px;'>★ Target</span>
      <span style='background:#E8F0FB;color:#0D3380;border:1px solid #0064B4;padding:3px 10px;border-radius:12px;'>● Subdomain</span>
      <span style='background:#FFF4E6;color:#7A4000;border:1px solid #E87B00;padding:3px 10px;border-radius:12px;'>◆ IP Address</span>
      <span style='background:#F5F8FF;color:#0D3380;border:1px solid #9AAFC8;padding:3px 10px;border-radius:12px;'>■ Open Port</span>
      <span style='background:#FDECEA;color:#7B1A14;border:1px solid #C0392B;padding:3px 10px;border-radius:12px;'>▼ Threat</span>
      <span style='background:#EAF5F0;color:#0F4A31;border:1px solid #1A7A52;padding:3px 10px;border-radius:12px;'>▲ Clean</span>
      <span style='background:#F5F0FF;color:#3B2B8C;border:1px solid #7B68EE;padding:3px 10px;border-radius:12px;'>⬭ Geo</span>
    </div>
    """, unsafe_allow_html=True)

    components.html(html, height=620, scrolling=False)
