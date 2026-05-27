import hashlib
import random
import re
import requests
import string
import streamlit as st


# ── Password Generator ─────────────────────────────────────

def generate_password(length=16, use_upper=True, use_digits=True, use_symbols=True):
    pool = list(string.ascii_lowercase)
    required = [random.choice(string.ascii_lowercase)]
    if use_upper:
        pool += list(string.ascii_uppercase)
        required.append(random.choice(string.ascii_uppercase))
    if use_digits:
        pool += list(string.digits)
        required.append(random.choice(string.digits))
    if use_symbols:
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        pool += list(symbols)
        required.append(random.choice(symbols))
    remaining = [random.choice(pool) for _ in range(length - len(required))]
    pwd = required + remaining
    random.shuffle(pwd)
    return "".join(pwd)


# ── Strength Checker ───────────────────────────────────────

def check_strength(password):
    score = 0
    feedback = []
    length = len(password)

    if length >= 16:
        score += 2
    elif length >= 12:
        score += 1
        feedback.append("Use 16+ characters for maximum strength")
    elif length >= 8:
        feedback.append("Password is short — aim for 12+ characters")
    else:
        feedback.append("Very short — use at least 8 characters")

    has_lower  = bool(re.search(r"[a-z]", password))
    has_upper  = bool(re.search(r"[A-Z]", password))
    has_digit  = bool(re.search(r"\d", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    score += sum([has_lower, has_upper, has_digit, has_symbol])

    if not has_lower:  feedback.append("Add lowercase letters")
    if not has_upper:  feedback.append("Add uppercase letters")
    if not has_digit:  feedback.append("Add numbers")
    if not has_symbol: feedback.append("Add special characters (!@#$...)")

    if re.search(r"(.)\1{2,}", password):
        score -= 1
        feedback.append("Avoid repeated characters (e.g. 'aaa')")
    if re.search(r"(012|123|234|345|456|567|678|789|890|abc|bcd|cde|qwe|asd)", password.lower()):
        score -= 1
        feedback.append("Avoid sequential patterns (e.g. '123', 'abc')")

    score = max(0, score)
    if score <= 2:
        label, color, bar_pct = "Weak",        "#C0392B", 20
    elif score <= 4:
        label, color, bar_pct = "Moderate",    "#E87B00", 50
    elif score <= 5:
        label, color, bar_pct = "Strong",      "#E87B00", 80
    else:
        label, color, bar_pct = "Very Strong", "#E87B00", 100

    return {
        "label": label, "color": color, "bar_pct": bar_pct,
        "feedback": feedback, "has_lower": has_lower, "has_upper": has_upper,
        "has_digit": has_digit, "has_symbol": has_symbol, "length": length,
    }


# ── HIBP k-Anonymity check ─────────────────────────────────

def check_hibp_password(password: str):
    try:
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        resp = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={"Add-Padding": "true"},
            timeout=10
        )
        if resp.status_code != 200:
            return None, f"HIBP API error: HTTP {resp.status_code}"
        for line in resp.text.splitlines():
            parts = line.split(":")
            if len(parts) == 2 and parts[0].strip() == suffix:
                return int(parts[1].strip()), None
        return 0, None
    except requests.exceptions.Timeout:
        return None, "Request timed out. Please try again."
    except Exception as e:
        return None, str(e)


# ── Main Render ────────────────────────────────────────────

def render_password_security():
    st.subheader("Password Security")
    st.markdown("Generate strong passwords, check their strength, or verify if they have been leaked.")

    if "pwd_active" not in st.session_state:
        st.session_state.pwd_active = "generator"

    # 3-button sub-nav
    col_a, col_b, col_c = st.columns(3)

    with col_a:
        t = "primary" if st.session_state.pwd_active == "generator" else "secondary"
        if st.button("🔑 Password Generator", key="btn_pwd_gen", type=t, use_container_width=True):
            st.session_state.pwd_active = "generator"
            st.rerun()

    with col_b:
        t = "primary" if st.session_state.pwd_active == "checker" else "secondary"
        if st.button("🔍 Strength Checker", key="btn_pwd_chk", type=t, use_container_width=True):
            st.session_state.pwd_active = "checker"
            st.rerun()

    with col_c:
        t = "primary" if st.session_state.pwd_active == "leak" else "secondary"
        if st.button("🚨 Leak Check", key="btn_pwd_leak", type=t, use_container_width=True):
            st.session_state.pwd_active = "leak"
            st.rerun()

    # ── Generator ─────────────────────────────────────────
    if st.session_state.pwd_active == "generator":
        st.markdown("#### Generate a Strong Password")
        col_len, col_opts = st.columns([1, 2])
        with col_len:
            pwd_length = st.slider("Length", 8, 64, 16, key="pwd_gen_length")
        with col_opts:
            st.markdown("<br>", unsafe_allow_html=True)
            use_upper   = st.checkbox("Uppercase (A-Z)",   value=True, key="pwd_upper")
            use_digits  = st.checkbox("Numbers (0-9)",     value=True, key="pwd_digits")
            use_symbols = st.checkbox("Symbols (!@#$...)", value=True, key="pwd_symbols")

        if st.button("Generate Password", key="pwd_generate_btn", type="primary", use_container_width=True):
            pwd = generate_password(pwd_length, use_upper, use_digits, use_symbols)
            st.session_state["generated_pwd"] = pwd

        if st.session_state.get("generated_pwd"):
            pwd = st.session_state.generated_pwd
            st.markdown(
                "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;border-radius:10px;"
                "padding:16px 20px;margin:14px 0;font-family:monospace;font-size:1.1rem;"
                "color:#0D3380;word-break:break-all;letter-spacing:0.05em;'>"
                + pwd + "</div>",
                unsafe_allow_html=True
            )
            st.code(pwd, language=None)
            result = check_strength(pwd)
            st.markdown(
                "<div style='font-size:0.88rem;color:#4A6A8A;margin-top:4px;'>"
                "Strength: <b style='color:" + result["color"] + ";'>" + result["label"] + "</b>"
                " &nbsp;·&nbsp; " + str(pwd_length) + " characters</div>",
                unsafe_allow_html=True
            )

        st.markdown(
            "<div style='font-size:0.8rem;color:#4A6A8A;line-height:1.9;margin-top:18px;'>"
            "<b style='color:#0D3380;'>Tips for strong passwords</b><br>"
            "Use 16+ characters with a mix of all character types.<br>"
            "Never reuse passwords across sites — use a password manager.<br>"
            "Passphrases (e.g. <i>Correct-Horse-Battery-Staple</i>) are also very strong."
            "</div>",
            unsafe_allow_html=True
        )

    # ── Strength Checker ──────────────────────────────────
    elif st.session_state.pwd_active == "checker":
        st.markdown("#### Check Password Strength")
        st.markdown(
            "<div style='font-size:0.87rem;color:#4A6A8A;margin-bottom:10px;'>"
            "Your password is never sent anywhere — all analysis runs locally."
            "</div>",
            unsafe_allow_html=True
        )

        pwd_to_check = st.text_input(
            "Enter password to analyse",
            type="password",
            placeholder="Type a password to check its strength...",
            key="pwd_check_input"
        )

        if pwd_to_check:
            result  = check_strength(pwd_to_check)
            label   = result["label"]
            color   = result["color"]
            bar_pct = result["bar_pct"]

            st.markdown(
                "<div style='margin:14px 0 6px;'>"
                "<div style='display:flex;justify-content:space-between;margin-bottom:4px;'>"
                "<span style='font-size:0.9rem;color:#0D3380;font-weight:600;'>Strength</span>"
                "<span style='font-size:0.9rem;color:" + color + ";font-weight:700;'>" + label + "</span>"
                "</div>"
                "<div style='background:#E8EFF8;border-radius:999px;height:10px;'>"
                "<div style='width:" + str(bar_pct) + "%;background:" + color + ";height:10px;"
                "border-radius:999px;'></div>"
                "</div></div>",
                unsafe_allow_html=True
            )

            criteria = [
                ("Length >= 12 chars",  result["length"] >= 12),
                ("Lowercase letters",   result["has_lower"]),
                ("Uppercase letters",   result["has_upper"]),
                ("Numbers",            result["has_digit"]),
                ("Special characters", result["has_symbol"]),
                ("Length >= 16 chars",  result["length"] >= 16),
            ]

            def _row(name, ok):
                bc = "#E87B00" if ok else "#C0392B"
                tc = "#0D3380" if ok else "#4A6A8A"
                ic = "✓" if ok else "✗"
                return (
                    "<div style='display:flex;align-items:center;gap:10px;padding:4px 0;'>"
                    "<span style='color:" + bc + ";font-size:1rem;font-weight:700;'>" + ic + "</span>"
                    "<span style='font-size:0.88rem;color:" + tc + ";'>" + name + "</span>"
                    "</div>"
                )

            rows_html = "".join(_row(n, o) for n, o in criteria)
            st.markdown(
                "<div style='background:#F0F6FF;border:1.5px solid #C2D4EC;border-radius:10px;"
                "padding:14px 18px;margin:10px 0;'>" + rows_html + "</div>",
                unsafe_allow_html=True
            )

            if result["feedback"]:
                tips_html = "".join(
                    "<li style='color:#0D3380;font-size:0.87rem;margin-bottom:4px;'>" + t + "</li>"
                    for t in result["feedback"]
                )
                st.markdown(
                    "<div style='margin-top:10px;'>"
                    "<b style='color:#0D3380;font-size:0.88rem;'>Suggestions to improve:</b>"
                    "<ul style='margin:6px 0 0 0;padding-left:20px;'>" + tips_html + "</ul></div>",
                    unsafe_allow_html=True
                )
            else:
                st.markdown(
                    "<div style='color:#E87B00;font-size:0.9rem;margin-top:8px;'>"
                    "Excellent! This password meets all strength criteria.</div>",
                    unsafe_allow_html=True
                )

    # ── Leak Check (HIBP k-Anonymity, fully inline) ───────
    elif st.session_state.pwd_active == "leak":
        st.markdown("#### Password Leak Check")
        st.markdown(
            "<div class='card'>"
            "Checks your password against <b>Have I Been Pwned</b>'s breach database "
            "using <b>k-Anonymity</b> — only the first 5 characters of a SHA-1 hash are "
            "ever sent to their servers. Your actual password <b>never leaves this page</b>."
            "</div>",
            unsafe_allow_html=True
        )

        leak_pwd = st.text_input(
            "Enter password to check",
            type="password",
            placeholder="Type your password and click Check...",
            key="leak_pwd_input",
            label_visibility="visible"
        )

        if st.button("Check for Leaks", key="leak_check_btn", type="primary", use_container_width=True):
            pwd_val = leak_pwd.strip() if leak_pwd else ""
            if not pwd_val:
                st.warning("Please enter a password to check.")
            else:
                with st.spinner("Checking against HIBP breach database..."):
                    count, error = check_hibp_password(pwd_val)

                if error:
                    st.error(f"Error: {error}")
                elif count is None:
                    st.error("Could not connect to HIBP. Please try again.")
                elif count == 0:
                    st.markdown(
                        "<div style='background:rgba(232,123,0,0.07);border:1.5px solid #E87B00;"
                        "border-radius:10px;padding:16px 20px;margin:12px 0;text-align:center;'>"
                        "<span style='font-size:1.4rem;'>✅</span><br>"
                        "<span style='color:#E87B00;font-weight:700;font-size:1.05rem;'>"
                        "Not Found in Any Breach</span><br>"
                        "<span style='color:#4A6A8A;font-size:0.88rem;'>"
                        "This password does not appear in any known data breach database. "
                        "Good — but still make sure it is unique and strong.</span>"
                        "</div>",
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        "<div style='background:rgba(192,57,43,0.07);border:1.5px solid #C0392B;"
                        "border-radius:10px;padding:16px 20px;margin:12px 0;text-align:center;'>"
                        "<span style='font-size:1.4rem;'>🔴</span><br>"
                        "<span style='color:#C0392B;font-weight:700;font-size:1.05rem;'>"
                        "Password Compromised!</span><br>"
                        "<span style='color:#0D3380;font-size:0.92rem;margin-top:4px;display:block;'>"
                        "Found <b style='color:#C0392B;'>" + f"{count:,}" + " time(s)</b> in known data breaches.</span><br>"
                        "<span style='color:#4A6A8A;font-size:0.85rem;'>"
                        "Change this password immediately on all sites where you use it, "
                        "and never reuse it again.</span>"
                        "</div>",
                        unsafe_allow_html=True
                    )

        st.markdown(
            "<div style='margin-top:18px;font-size:0.8rem;color:#4A6A8A;line-height:1.9;'>"
            "<b style='color:#0D3380;'>How k-Anonymity keeps you safe</b><br>"
            "Your password is hashed with SHA-1 locally. Only the first 5 characters of that "
            "hash are sent to HIBP's servers. They return all matching hash suffixes, and the "
            "full comparison happens right here — your password never travels over the network."
            "</div>",
            unsafe_allow_html=True
        )
