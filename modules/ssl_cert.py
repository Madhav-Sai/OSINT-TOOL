import streamlit as st
from datetime import datetime, timezone


def render_ssl_info(attrs: dict):
    cert = attrs.get("last_https_certificate")
    if not cert:
        st.info("ℹ️ No SSL certificate data available")
        return

    valid_to = cert.get("validity", {}).get("not_after")
    status, color = "N/A", "yellow"

    try:
        if valid_to:
            expiry = (
                datetime.fromisoformat(str(valid_to).replace("Z", "+00:00"))
                if "T" in str(valid_to)
                else datetime.strptime(str(valid_to), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            )
            days = (expiry - datetime.now(timezone.utc)).days
            if days <= 0:
                status, color = "EXPIRED", "red"
            elif days <= 30:
                status, color = f"{days} days", "red"
            elif days <= 90:
                status, color = f"{days} days", "yellow"
            else:
                status, color = f"{days} days", "green"
    except Exception as e:
        st.warning(f"⚠️ Could not parse cert expiry: {e}")

    st.subheader("TLS / SSL Certificate Intelligence")

    san = cert.get("extensions", {}).get("subject_alternative_name", [])
    san_display = ", ".join(san[:5]) + ("…" if len(san) > 5 else "") if san else "N/A"

    st.markdown(f"""<div class="card">
    <b>Issuer:</b> {cert.get("issuer",{}).get("O","N/A")}<br>
    <b>Subject CN:</b> {cert.get("subject",{}).get("CN","N/A")}<br>
    <b>SANs:</b> {san_display}<br>
    <b>Valid Till:</b> {valid_to}<br>
    <b>Days Remaining:</b> <span class="{color}">{status}</span>
    </div>""", unsafe_allow_html=True)
    st.markdown(
        "<div style='font-size:0.78rem;color:#4A6A8A;margin-top:-4px;margin-bottom:8px;"
        "padding-left:4px;'>"
        "<span style='color:#1A7A52;font-weight:600;'>Green</span> = Valid (&gt;90 days) &nbsp;|&nbsp; "
        "<span style='color:#F5C842;font-weight:600;'>Yellow</span> = Expiring soon (30–90 days) &nbsp;|&nbsp; "
        "<span style='color:#C0392B;font-weight:600;'>Red</span> = Expired or critical (&lt;30 days)"
        "</div>",
        unsafe_allow_html=True
    )
