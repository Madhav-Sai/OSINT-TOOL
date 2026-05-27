import os
import sys
import streamlit as st
from dotenv import load_dotenv
from PIL import Image

sys.path.insert(0, os.path.dirname(__file__))

st.set_page_config(
    page_title="OSINT Platform",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

load_dotenv()

from utils.helpers import load_css
load_css(os.path.join(os.path.dirname(__file__), "assets", "style.css"))

# Theme overrides removed here in favor of unified assets/style.css

from utils.helpers               import detect_input_type
from modules.reputation          import (fetch_vt_domain, fetch_vt_ip,
                                         render_ip_reputation, render_domain_reputation)
from modules.ssl_cert            import render_ssl_info
from modules.dns_intel           import render_dns_domain, render_dns_ip
from modules.subdomains          import (render_subdomains, render_subdomains_from_ip)
from modules.typosquatting       import render_typosquatting
from modules.sherlock_hunt       import render_sherlock
from modules.hash_tool           import render_hash_tool
from modules.network_graph       import render_network_graph
from modules.cyber_news          import render_cyber_news

VT_API_KEY        = os.getenv("VT_API_KEY")
SHODAN_API_KEY    = os.getenv("SHODAN_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIEWDNS_API_KEY   = os.getenv("VIEWDNS_API_KEY")

for key, val in [
    ("sherlock_results",        []),
    ("sherlock_scanning",       False),
    ("sherlock_username",       None),
    ("sherlock_stop_requested", False),
    ("active_filter",           "All"),
    ("pwd_active",              "generator"),
    ("ng_subs",                 True),
    ("ng_ports",                True),
    ("ng_threat",               True),
]:
    if key not in st.session_state:
        st.session_state[key] = val

NAV_TABS = [
    "All",
    "IP/Domain Reputation",
    "TLS / SSL Certificate Intelligence",
    "DNS Intelligence",
    "Subdomain Discovery",
    "Typosquatting Analysis",
    "Network Graph",
    "Username Hunt",
    "Breach Check",
    "Hash and Integrity",
    "Password Security",
    "Security Support Hub",
    "Cyber News",
]

# ═══════════════════════════════════════════════════════════
# HEADER ROW — title left, logo top-right (original size)
# ═══════════════════════════════════════════════════════════
logo_path = os.path.join(os.path.dirname(__file__), "download-removebg-preview.png")
col_title, col_logo = st.columns([4, 1])

with col_title:
    st.markdown("""
<div class='osint-header'>
    <h1>OSINT Platform</h1>
    <p>Open Source Intelligence Gathering Tool</p>
</div>
""", unsafe_allow_html=True)

with col_logo:
    if os.path.exists(logo_path):
        try:
            logo = Image.open(logo_path)
            st.image(logo, width=126)
        except Exception:
            pass

# ═══════════════════════════════════════════════════════════
# CUSTOM NAV FILTER PILLS — wraps to 2 lines, equal spacing,
# full label always visible. st.pills handles layout natively.
# ═══════════════════════════════════════════════════════════
selected_pill = st.pills(
    "Filter",
    NAV_TABS,
    default=st.session_state.active_filter,
    key="nav_pills",
    label_visibility="collapsed",
)
if selected_pill and selected_pill != st.session_state.active_filter:
    st.session_state.active_filter = selected_pill
    st.rerun()
if selected_pill:
    st.session_state.active_filter = selected_pill

selected_filter = st.session_state.active_filter

# JS fallback: force active gradient on the selected pill button
# Works regardless of which aria attribute Streamlit uses in the current version
active_pill_label = selected_filter.replace("'", "\\'")
st.markdown(f"""
<script>
(function applyActivePill() {{
    const label = '{active_pill_label}';
    const container = document.querySelector('[data-testid="stPillsContainer"]');
    if (!container) {{ setTimeout(applyActivePill, 120); return; }}
    container.querySelectorAll('button').forEach(btn => {{
        const isActive = btn.innerText.trim() === label;
        btn.style.background    = isActive ? '#0064B4' : '';
        btn.style.color         = isActive ? '#ffffff' : '';
        btn.style.border        = isActive ? 'none' : '';
        btn.style.fontWeight    = isActive ? '700' : '';
        btn.style.boxShadow     = isActive ? '0 2px 10px rgba(0,60,140,0.25)' : '';
        btn.style.textShadow    = isActive ? '0 1px 2px rgba(0,0,0,0.25)' : '';
    }});
}})();
</script>
""", unsafe_allow_html=True)


def should_show(tool_name: str) -> bool:
    return selected_filter in ("All", tool_name)


# ═══════════════════════════════════════════════════════════
# STANDALONE TOOLS
# ═══════════════════════════════════════════════════════════

if selected_filter == "Breach Check":
    import os, requests as _req

    HIBP_API_KEY = os.getenv("HIBP_API_KEY", "")

    def _check_hibp_email(email: str):
        try:
            headers = {
                "hibp-api-key": HIBP_API_KEY,
                "user-agent":   "OSINT-Platform",
            }
            resp = _req.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email.strip()}",
                headers=headers,
                params={"truncateResponse": "false"},
                timeout=12,
            )
            if resp.status_code == 200:
                return resp.json(), None
            elif resp.status_code == 404:
                return [], None
            elif resp.status_code == 401:
                return None, "HIBP API key missing or invalid. Set the HIBP_API_KEY environment variable."
            elif resp.status_code == 429:
                return None, "Rate limited by HIBP. Please wait a moment and try again."
            else:
                return None, f"HIBP API error: HTTP {resp.status_code}"
        except _req.exceptions.Timeout:
            return None, "Request timed out. Please try again."
        except Exception as e:
            return None, str(e)

    st.subheader("Breach Check — Have I Been Pwned")
    st.markdown(
        "<div class='card'>Check if your email address has been exposed in a known data breach. "
        "Results are fetched directly from <b>Have I Been Pwned</b> and displayed here.</div>",
        unsafe_allow_html=True
    )

    breach_email = st.text_input(
        "Email address",
        placeholder="youremail@example.com",
        key="breach_email_input"
    )

    if st.button("Check for Breaches", key="breach_check_btn", type="primary", use_container_width=True):
        email_val = breach_email.strip() if breach_email else ""
        if not email_val or "@" not in email_val:
            st.warning("Please enter a valid email address.")
        else:
            with st.spinner("Checking against HIBP breach database..."):
                breaches, err = _check_hibp_email(email_val)

            if err:
                st.error(f"Error: {err}")
            elif breaches is None:
                st.error("Could not connect to HIBP. Please try again.")
            elif len(breaches) == 0:
                st.markdown(
                    "<div style='background:rgba(232,123,0,0.07);border:1.5px solid #E87B00;"
                    "border-radius:10px;padding:16px 20px;margin:12px 0;text-align:center;'>"
                    "<span style='font-size:1.4rem;'>✅</span><br>"
                    "<span style='color:#E87B00;font-weight:700;font-size:1.05rem;'>"
                    "No Breaches Found</span><br>"
                    "<span style='color:#4A6A8A;font-size:0.88rem;'>"
                    f"Good news — <b>{email_val}</b> does not appear in any known data breach.</span>"
                    "</div>",
                    unsafe_allow_html=True
                )
            else:
                count = len(breaches)
                st.markdown(
                    "<div style='background:rgba(192,57,43,0.07);border:1.5px solid #C0392B;"
                    "border-radius:10px;padding:16px 20px;margin:12px 0;text-align:center;'>"
                    "<span style='font-size:1.4rem;'>🔴</span><br>"
                    "<span style='color:#C0392B;font-weight:700;font-size:1.05rem;'>"
                    "Email Found in Data Breaches!</span><br>"
                    "<span style='color:#0D3380;font-size:0.92rem;margin-top:4px;display:block;'>"
                    f"<b style='color:#C0392B;'>{count} breach{'es' if count > 1 else ''}</b> found for <b>{email_val}</b>.</span><br>"
                    "<span style='color:#4A6A8A;font-size:0.85rem;'>"
                    "Change your passwords on the affected sites and enable two-factor authentication.</span>"
                    "</div>",
                    unsafe_allow_html=True
                )

                for b in breaches:
                    name        = b.get("Name", "Unknown")
                    title       = b.get("Title", name)
                    domain      = b.get("Domain", "")
                    breach_date = b.get("BreachDate", "Unknown date")
                    pwn_count   = b.get("PwnCount", 0)
                    data_classes= b.get("DataClasses", [])
                    verified    = b.get("IsVerified", False)
                    sensitive   = b.get("IsSensitive", False)

                    tags_html = ""
                    if verified:
                        tags_html += "<span style='background:#C0392B;color:#fff;border-radius:4px;padding:2px 8px;font-size:0.75rem;margin-right:4px;'>Verified</span>"
                    if sensitive:
                        tags_html += "<span style='background:#0D3380;color:#fff;border-radius:4px;padding:2px 8px;font-size:0.75rem;margin-right:4px;'>Sensitive</span>"

                    classes_html = ""
                    if data_classes:
                        classes_html = "".join(
                            f"<span style='background:#E8EFF8;color:#0D3380;border-radius:4px;"
                            f"padding:2px 8px;font-size:0.78rem;margin:2px 2px 0 0;display:inline-block;'>{dc}</span>"
                            for dc in data_classes
                        )

                    domain_line = f"<span style='color:#4A6A8A;font-size:0.82rem;'>{domain}</span><br>" if domain else ""

                    st.markdown(
                        "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;border-radius:10px;"
                        "padding:14px 18px;margin:8px 0;'>"
                        f"<div style='display:flex;justify-content:space-between;align-items:center;'>"
                        f"<span style='font-weight:700;color:#0D3380;font-size:0.98rem;'>{title}</span>"
                        f"<span style='color:#4A6A8A;font-size:0.82rem;'>{breach_date}</span></div>"
                        f"{domain_line}"
                        f"<div style='margin:4px 0;'>{tags_html}</div>"
                        f"<div style='color:#4A6A8A;font-size:0.83rem;margin:4px 0;'>"
                        f"<b style='color:#0D3380;'>{pwn_count:,}</b> accounts compromised</div>"
                        f"<div style='margin-top:6px;'>{classes_html}</div>"
                        "</div>",
                        unsafe_allow_html=True
                    )

    st.markdown(
        "<div style='margin-top:18px;font-size:0.8rem;color:#4A6A8A;line-height:1.9;'>"
        "<b style='color:#0D3380;'>About Have I Been Pwned</b><br>"
        "Free service by security researcher Troy Hunt. Monitors billions of breached credentials "
        "across major breaches (LinkedIn, Adobe, etc.). Your email is never stored or shared."
        "</div>",
        unsafe_allow_html=True
    )
    st.stop()

if selected_filter == "Hash and Integrity":
    render_hash_tool()
    st.stop()

if selected_filter == "Password Security":
    from modules.password_security import render_password_security
    render_password_security()
    st.stop()

if selected_filter == "Security Support Hub":
    from modules.security_hub import render_security_hub
    render_security_hub()
    st.stop()

if selected_filter == "Cyber News":
    render_cyber_news()
    st.stop()


# ═══════════════════════════════════════════════════════════
# QUERY-BASED TOOLS
# ═══════════════════════════════════════════════════════════

# ── Contextual display options (left-aligned) ─────────────
if selected_filter in ("All", "Subdomain Discovery", "Typosquatting Analysis"):
    if selected_filter == "All":
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("##### Subdomain Display")
            sub_limit = st.selectbox("Number of subdomains", [15, 50, "All"], index=0, key="sub_limit")
        with col2:
            st.markdown("##### Typosquatting Display")
            typo_limit = st.selectbox("Number of typo domains", [10, 25, 50, "All"], index=0, key="typo_limit")
    elif selected_filter == "Subdomain Discovery":
        col1, _spacer = st.columns([1, 1])
        with col1:
            st.markdown("##### Subdomain Display")
            sub_limit = st.selectbox("Number of subdomains", [15, 50, "All"], index=0, key="sub_limit")
        typo_limit = 10
    else:
        col1, _spacer = st.columns([1, 1])
        with col1:
            st.markdown("##### Typosquatting Display")
            typo_limit = st.selectbox("Number of typo domains", [10, 25, 50, "All"], index=0, key="typo_limit")
        sub_limit = 15
else:
    sub_limit  = 15
    typo_limit = 10

# ── Context-aware query label ─────────────────────────────
QUERY_LABELS = {
    "All": (
        "IP / Domain / URL / Email / Username",
        "e.g.  8.8.8.8  ·  google.com  ·  https://example.com  ·  user@example.com  ·  john_doe"
    ),
    "IP/Domain Reputation": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  google.com"
    ),
    "TLS / SSL Certificate Intelligence": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  example.com"
    ),
    "DNS Intelligence": (
        "IP Address or Domain",
        "e.g.  8.8.8.8  or  example.com"
    ),
    "Subdomain Discovery": (
        "Domain",
        "e.g.  example.com"
    ),
    "Typosquatting Analysis": (
        "Domain",
        "e.g.  example.com"
    ),
    "Username Hunt": (
        "Username",
        "e.g.  john_doe"
    ),
}

q_label, q_placeholder = QUERY_LABELS.get(
    selected_filter,
    ("IP / Domain / URL / Email / Username",
     "e.g.  8.8.8.8  ·  google.com  ·  https://example.com")
)

query = st.text_input(q_label, placeholder=q_placeholder)

# ── Network Graph options — shown before search so user can configure first ──
if selected_filter in ("All", "Network Graph"):
    with st.expander("🕸 Network Graph Options", expanded=(selected_filter == "Network Graph")):
        gc1, gc2, gc3 = st.columns(3)
        gc1.toggle("Include subdomains",       key="ng_subs")
        gc2.toggle("Include open ports (Shodan)", key="ng_ports")
        gc3.toggle("Include threat tags",      key="ng_threat")

# ── API Key Status ────────────────────────────────────────
with st.expander("API Key Status"):
    st.markdown(f"""
    - **VirusTotal:**  {'Configured' if VT_API_KEY        else 'Missing'}
    - **Shodan:**      {'Configured' if SHODAN_API_KEY     else 'Missing'}
    - **AbuseIPDB:**   {'Configured' if ABUSEIPDB_API_KEY  else 'Missing'}
    - **ViewDNS:**     {'Configured' if VIEWDNS_API_KEY    else 'Missing'}
    - **Sherlock:**    Local install (no key needed)
    """)

if st.button("Search", use_container_width=True, type="primary"):
    if not query:
        st.warning("Please enter a value to search.")
    else:
        input_type = detect_input_type(query)

        if input_type == "UNKNOWN":
            st.error("Invalid input. Please enter a valid IP, domain, URL, email, or username.")

        elif input_type == "IP":
            st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>IP address detected: <b>{query}</b></div>", unsafe_allow_html=True)

            if should_show("IP/Domain Reputation"):
                render_ip_reputation(query)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data…"):
                    vt_ssl = fetch_vt_ip(query)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence") and VIEWDNS_API_KEY:
                render_dns_ip(query)

            if should_show("Subdomain Discovery"):
                with st.spinner("Fetching VirusTotal resolutions…"):
                    vt2 = fetch_vt_ip(query)
                render_subdomains_from_ip(query, vt2, sub_limit)

            if should_show("Network Graph"):
                render_network_graph(query)

        elif input_type == "DOMAIN" or input_type.startswith("DOMAIN:"):
            if input_type.startswith("DOMAIN:"):
                domain_to_check = input_type.split(":", 1)[1]
                st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>URL detected: **{query}**</div>", unsafe_allow_html=True)
                st.info(f"Analysing domain: **{domain_to_check}**")
            else:
                domain_to_check = query
                st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Domain detected: **{query}**</div>", unsafe_allow_html=True)

            if should_show("IP/Domain Reputation"):
                render_domain_reputation(domain_to_check)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data…"):
                    vt_ssl = fetch_vt_domain(domain_to_check)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence") and VIEWDNS_API_KEY:
                render_dns_domain(domain_to_check)

            if should_show("Subdomain Discovery"):
                render_subdomains(domain_to_check, sub_limit)

            if should_show("Typosquatting Analysis"):
                render_typosquatting(domain_to_check, typo_limit)

            if should_show("Network Graph"):
                render_network_graph(domain_to_check)

        elif input_type == "EMAIL":
            parts = query.strip().split("@")
            if len(parts) < 2 or not parts[1]:
                st.error("Invalid email address. Please include the domain part (e.g. user@example.com)")
                st.stop()
            email_domain = parts[1].lower()
            st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Email detected: **{query}**</div>", unsafe_allow_html=True)
            st.info(f"Analysing domain: **{email_domain}**")

            if should_show("IP/Domain Reputation"):
                render_domain_reputation(email_domain)

            if should_show("TLS / SSL Certificate Intelligence"):
                with st.spinner("Fetching SSL certificate data…"):
                    vt_ssl = fetch_vt_domain(email_domain)
                if vt_ssl and "data" in vt_ssl:
                    render_ssl_info(vt_ssl["data"]["attributes"])

            if should_show("DNS Intelligence") and VIEWDNS_API_KEY:
                render_dns_domain(email_domain)

            if should_show("Subdomain Discovery"):
                render_subdomains(email_domain, sub_limit)

            if should_show("Typosquatting Analysis"):
                render_typosquatting(email_domain, typo_limit)

            if should_show("Network Graph"):
                render_network_graph(email_domain)

        elif input_type == "USERNAME":
            st.markdown(f"<div style='background:#FFF4E6;border:1.5px solid #F0C070;border-left:4px solid #E87B00;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>Username detected: **{query}**</div>", unsafe_allow_html=True)
            if should_show("Username Hunt"):
                render_sherlock(query)

# ═══════════════════════════════════════════════════════════
# FOOTER
# ═══════════════════════════════════════════════════════════
st.markdown("""
<div class="caution-footer">
<span>DISCLAIMER</span> — This tool is intended for
<b>authorised security research and educational purposes only</b>.<br>
Misuse of this platform may violate applicable laws and regulations.
Always obtain proper authorisation before scanning any target.<br>
<i>Built for OSINT researchers · Use responsibly and ethically</i>
</div>
""", unsafe_allow_html=True)
