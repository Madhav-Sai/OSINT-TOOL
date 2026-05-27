"""
Truecaller Phone Lookup Module
==============================
Truecaller does NOT have a public/free official API.
Two approaches are available:

APPROACH 1 (Recommended) — truecallerpy (unofficial, reverse-engineered)
  pip install truecallerpy
  Requires a one-time OTP login with your real phone number.
  Set TRUECALLER_AUTH_TOKEN in your .env after login.

APPROACH 2 — numverify / abstract API (basic carrier info, no name)
  Set NUMVERIFY_API_KEY in your .env (free tier: 250 requests/month)
  https://numverify.com/

HOW TO GET TRUECALLER TOKEN:
  1. pip install truecallerpy
  2. Run: python -c "from truecallerpy import TruecallerPy; t = TruecallerPy('+91XXXXXXXXXX'); t.generate_otp()"
  3. Enter the OTP you receive
  4. Copy the auth token printed and add to .env as TRUECALLER_AUTH_TOKEN
"""

import os
import streamlit as st
import requests

TRUECALLER_AUTH_TOKEN = os.getenv("TRUECALLER_AUTH_TOKEN")
NUMVERIFY_API_KEY     = os.getenv("NUMVERIFY_API_KEY")


def _lookup_truecallerpy(phone: str) -> dict:
    """Uses unofficial truecallerpy library."""
    try:
        from truecallerpy import TruecallerPy
        tc = TruecallerPy(auth_token=TRUECALLER_AUTH_TOKEN)
        result = tc.search_phone_number(phone, "IN")
        if result and result.get("data"):
            d = result["data"][0]
            return {
                "name":     d.get("name", "Unknown"),
                "phones":   ", ".join([p.get("e164Format", "") for p in d.get("phones", [])]),
                "tags":     ", ".join(d.get("tags", [])),
                "score":    d.get("score", "N/A"),
                "address":  d.get("addresses", [{}])[0].get("city", "N/A") if d.get("addresses") else "N/A",
                "internet_addresses": ", ".join(
                    [ia.get("id", "") for ia in d.get("internetAddresses", [])]
                ),
                "source": "Truecaller"
            }
        return {}
    except ImportError:
        return {"error": "truecallerpy not installed. Run: pip install truecallerpy"}
    except Exception as e:
        return {"error": str(e)}


def _lookup_numverify(phone: str) -> dict:
    """Uses numverify.com for basic carrier/country info."""
    if not NUMVERIFY_API_KEY:
        return {"error": "NUMVERIFY_API_KEY not set in .env"}
    try:
        r = requests.get(
            "http://apilayer.net/api/validate",
            params={"access_key": NUMVERIFY_API_KEY, "number": phone, "format": 1},
            timeout=10
        )
        if r.status_code == 200:
            d = r.json()
            if d.get("valid"):
                return {
                    "number":        d.get("international_format", phone),
                    "country":       d.get("country_name", "N/A"),
                    "carrier":       d.get("carrier", "N/A"),
                    "line_type":     d.get("line_type", "N/A"),
                    "location":      d.get("location", "N/A"),
                    "source": "Numverify"
                }
            else:
                return {"error": "Phone number is invalid or not found"}
        return {"error": f"API error: {r.status_code}"}
    except Exception as e:
        return {"error": str(e)}


def render_truecaller_lookup():
    st.subheader("📞 Phone Lookup")
    st.markdown(
        "Look up leaked or public information associated with a phone number."
    )

    # Determine available method
    has_truecaller = bool(TRUECALLER_AUTH_TOKEN)
    has_numverify  = bool(NUMVERIFY_API_KEY)

    if not has_truecaller and not has_numverify:
        st.warning(
            "⚠️ No phone lookup API configured. "
            "Add `TRUECALLER_AUTH_TOKEN` or `NUMVERIFY_API_KEY` to your `.env` file."
        )
        st.markdown("""
        <div class="card">
            <b>Setup Instructions:</b><br><br>
            <b>Option A — Truecaller (name + social info):</b><br>
            <code>pip install truecallerpy</code><br>
            Run the OTP flow (see modules/truecaller_lookup.py for details)<br>
            Add <code>TRUECALLER_AUTH_TOKEN=your_token</code> to <code>.env</code><br><br>
            <b>Option B — Numverify (carrier / country info):</b><br>
            Get a free key at <a href="https://numverify.com" target="_blank">numverify.com</a><br>
            Add <code>NUMVERIFY_API_KEY=your_key</code> to <code>.env</code>
        </div>
        """, unsafe_allow_html=True)
        return

    col_l, col_r = st.columns([2, 1])
    with col_l:
        phone_input = st.text_input(
            "Enter phone number",
            placeholder="+91 9876543210  or  9876543210",
            key="truecaller_phone_input"
        )
    with col_r:
        st.markdown("<br>", unsafe_allow_html=True)
        method = st.selectbox(
            "Lookup source",
            (["Truecaller"] if has_truecaller else []) +
            (["Numverify (carrier info)"] if has_numverify else []),
            key="tc_method"
        )

    if st.button("🔍 Lookup Number", type="primary", use_container_width=True, key="tc_search"):
        raw = phone_input.strip().replace(" ", "").replace("-", "")
        if not raw:
            st.warning("⚠️ Please enter a phone number")
            return

        # Normalise to E.164 for India if no country code
        if raw.startswith("0"):
            raw = "+91" + raw[1:]
        elif not raw.startswith("+"):
            raw = "+91" + raw

        with st.spinner("🔄 Looking up…"):
            if "Truecaller" in method:
                result = _lookup_truecallerpy(raw)
            else:
                result = _lookup_numverify(raw)

        if "error" in result:
            st.error(f"❌ {result['error']}")
        elif not result:
            st.info("ℹ️ No results found for this number.")
        else:
            source = result.pop("source", "Unknown")
            st.markdown(f"<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;border-left:4px solid #0064B4;border-radius:8px;padding:10px 16px;color:#0D3380;font-size:0.92rem;margin-bottom:8px;'>✅ Result from **{source}**</div>", unsafe_allow_html=True)
            rows = "".join(
                f"<tr><td><b style='color:#F59E0B;'>{k.replace('_',' ').title()}</b></td>"
                f"<td style='color:#D6D3D1;'>{v}</td></tr>"
                for k, v in result.items() if v and v != "N/A"
            )
            st.markdown(f"""
            <table class="meta-table">
                <thead><tr><th>Field</th><th>Value</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
            """, unsafe_allow_html=True)

    st.markdown("""
    <div style='margin-top:16px;font-size:0.8rem;color:#78716C;'>
    ⚖️ Use this feature only to look up your own number or with explicit consent.
    Reverse phone lookups on others without consent may violate privacy laws.
    </div>
    """, unsafe_allow_html=True)
