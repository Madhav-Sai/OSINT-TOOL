import streamlit as st


def render_security_hub():
    st.subheader("Security Support Hub — India")
    st.markdown(
        "Quick access to emergency cyber contacts, reporting portals, and safety resources.",
        unsafe_allow_html=True
    )

    st.markdown("---")

    st.markdown("""
    <div class="hub-card" style="border-left-color:#C0392B;">
        <h4>Emergency — Financial Fraud Helpline</h4>
        <div class="hub-body">
            <b>Helpline:</b> <span style="font-size:1.4rem;color:#0064B4;font-weight:700;">1930</span><br>
            <b>Use for:</b> UPI fraud, bank scams, immediate financial threats<br>
            <b>Run by:</b> Indian Cyber Crime Coordination Centre (I4C)<br>
            <span style="color:#4A6A8A;font-size:0.83rem;">Call immediately — the sooner you report, the better the chance of recovery.</span>
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hub-card">
        <h4>Report Cyber Crime — National Portal</h4>
        <div class="hub-body">
            <b>Portal:</b> <a href="https://cybercrime.gov.in" target="_blank">cybercrime.gov.in</a><br>
            <b>Use for:</b> Online fraud · Social media abuse · Hacking · Identity theft · Women &amp; children related crimes
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hub-card" style="border-left-color:#0064B4;">
        <h4>Report Cyber Incidents — CERT-In</h4>
        <div class="hub-body">
            <b>Portal:</b> <a href="https://www.cert-in.org.in" target="_blank">cert-in.org.in</a><br>
            <b>Use for:</b> Major cyber attacks · Website vulnerabilities · Phishing campaigns
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="hub-card" style="border-left-color:#4A6A8A;">
        <h4>Emergency Number — 112</h4>
        <div class="hub-body">
            <b>Helpline:</b> 112<br>
            <b>Use for:</b> Threats · Blackmail · Cyberstalking · Immediate danger<br>
            <b>Managed by:</b> Emergency Response Support System (ERSS)
        </div>
    </div>
    """, unsafe_allow_html=True)
   
    st.markdown("""
    <div class="hub-card" style="border-left-color:#4A6A8A;">
        <h4>International Support — Interpol</h4>
        <div class="hub-body">
            <b>Portal:</b> <a href="https://www.interpol.int" target="_blank">interpol.int</a><br>
            <b>Use for:</b> Global cybercrime awareness · Large-scale international threats
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")

    st.markdown("""
    <div class="hub-note">
        <b style="color:#0D3380;">Safety Tips</b><br>
        Always report fraud <b>immediately</b> — within minutes if possible.<br>
        Never share OTPs, PINs, or passwords with anyone.<br>
        Use strong, unique passwords for every account.<br>
        Enable <b>Two-Factor Authentication (2FA)</b> on all accounts.<br>
        Verify links before clicking — hover to preview the destination URL.<br>
        Be cautious of emails or SMS messages asking for personal or financial information.
    </div>
    """, unsafe_allow_html=True)
