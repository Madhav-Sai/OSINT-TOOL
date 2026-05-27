import hashlib
import os
import requests
import streamlit as st
from typing import Optional

VT_API_KEY = os.getenv("VT_API_KEY")

HASH_ALGORITHMS = {
    "MD5":       "md5",
    "SHA-1":     "sha1",
    "SHA-224":   "sha224",
    "SHA-256":   "sha256",
    "SHA-384":   "sha384",
    "SHA-512":   "sha512",
    "SHA3-224":  "sha3_224",
    "SHA3-256":  "sha3_256",
    "SHA3-384":  "sha3_384",
    "SHA3-512":  "sha3_512",
    "BLAKE2b":   "blake2b",
    "BLAKE2s":   "blake2s",
}

HASH_LENGTHS = {
    "md5":       32,
    "sha1":      40,
    "sha224":    56,
    "sha256":    64,
    "sha384":    96,
    "sha512":    128,
    "sha3_224":  56,
    "sha3_256":  64,
    "sha3_384":  96,
    "sha3_512":  128,
    "blake2b":   128,
    "blake2s":   64,
}


def compute_hash(data: bytes, algorithm: str) -> Optional[str]:
    try:
        h = hashlib.new(algorithm)
        h.update(data)
        return h.hexdigest()
    except Exception:
        return None


def render_hash_tool():
    st.subheader("Hash & Integrity")
    st.markdown("Compute cryptographic hashes, verify file integrity, and check file hashes.")

    tab1, tab2, tab3 = st.tabs(["Hash Generator", "Integrity Checker", "Hash Lookup"])

    # ── Tab 1: Hash Generator ──────────────────────────────
    with tab1:
        col_algo, col_input = st.columns([1, 2])

        with col_algo:
            selected_algo_name = st.selectbox(
                "Hash Algorithm",
                list(HASH_ALGORITHMS.keys()),
                key="hash_algo_select"
            )
            algo_key = HASH_ALGORITHMS[selected_algo_name]

        with col_input:
            input_mode = st.radio(
                "Input Type",
                ["Upload File", "Enter Text"],
                horizontal=True,
                key="hash_input_mode"
            )

        result = None
        file_info_html = ""

        if input_mode == "Upload File":
            uploaded = st.file_uploader(
                "Upload any file to hash",
                key="hash_file_upload",
                help="Supports any file type"
            )
            if uploaded is not None:
                data = uploaded.read()
                result = compute_hash(data, algo_key)
                file_info_html = (
                    f"<div style='margin-top:8px;'>"
                    f"<b style='color:#4A6A8A;'>File:</b> "
                    f"<span style='color:#0D3380;'>{uploaded.name}</span> &nbsp;"
                    f"<b style='color:#4A6A8A;'>Size:</b> "
                    f"<span style='color:#F0EEFF;'>{len(data):,} bytes</span>"
                    f"</div>"
                )
        else:
            text_input = st.text_area(
                "Enter text to hash",
                placeholder="Type or paste any text here…",
                key="hash_text_input",
                height=120
            )
            if st.button("Generate Hash", key="gen_hash_btn", type="primary", use_container_width=True):
                if text_input:
                    st.session_state["hash_result_cache"] = compute_hash(text_input.encode("utf-8"), algo_key)
                    st.session_state["hash_algo_cache"] = selected_algo_name
                else:
                    st.warning("Please enter some text first.")
            if text_input:
                result = compute_hash(text_input.encode("utf-8"), algo_key)

        # ── Single result display with copy ───────────────
        if result:
            if file_info_html:
                st.markdown(file_info_html, unsafe_allow_html=True)
            st.markdown(f"**{selected_algo_name} Hash:**")
            st.markdown(
                f"<div class='hash-result-box'>{result}</div>",
                unsafe_allow_html=True
            )
            st.markdown(
                f"<span style='color:#4A6A8A;font-size:0.8rem;'>Length: {len(result)} hex chars</span>",
                unsafe_allow_html=True
            )

        st.markdown("---")
        st.markdown("""
        <div style='font-size:0.8rem;color:#4A6A8A;line-height:1.9;'>
        <b style='color:#0D3380;'>Algorithm Reference</b><br>
        <b>MD5</b> (32 chars) — Fast, not suitable for cryptographic security<br>
        <b>SHA-1</b> (40 chars) — Legacy standard, avoid for new implementations<br>
        <b>SHA-256</b> (64 chars) — Recommended for general use<br>
        <b>SHA-512</b> (128 chars) — Higher security margin, larger output<br>
        <b>SHA3-256 / SHA3-512</b> — Next-generation standard, strongest security<br>
        <b>BLAKE2b / BLAKE2s</b> — Fastest secure hashing algorithm
        </div>
        """, unsafe_allow_html=True)

    # ── Tab 2: Integrity Checker ───────────────────────────
    with tab2:
        st.markdown("**Verify file integrity by pasting both hashes and comparing them.**")

        ic_algo_name = st.selectbox(
            "Hash Algorithm",
            list(HASH_ALGORITHMS.keys()),
            key="ic_algo_select"
        )
        ic_algo_key = HASH_ALGORITHMS[ic_algo_name]
        expected_len = HASH_LENGTHS.get(ic_algo_key, 0)

        col_l, col_r = st.columns(2)

        with col_l:
            st.markdown("#### Computed Hash")
            computed_hash_input = st.text_area(
                "Paste your computed hash here",
                placeholder=f"Paste the {ic_algo_name} hash you computed…",
                key="ic_computed_hash",
                height=120
            )
            if computed_hash_input.strip():
                actual_len_l = len(computed_hash_input.strip().replace(" ", ""))
                color_l = "#E87B00" if actual_len_l == expected_len else "#E87B00"
                st.markdown(
                    f"<span style='color:{color_l};font-size:0.82rem;'>"
                    f"Length: {actual_len_l} chars (expected {expected_len})</span>",
                    unsafe_allow_html=True
                )

        with col_r:
            st.markdown("#### Official Hash")
            known_hash = st.text_area(
                "Paste the official hash here",
                placeholder=f"Paste {ic_algo_name} hash from the official source…",
                key="ic_known_hash",
                height=120
            )
            if known_hash.strip():
                actual_len_r = len(known_hash.strip().replace(" ", ""))
                color_r = "#E87B00" if actual_len_r == expected_len else "#E87B00"
                st.markdown(
                    f"<span style='color:{color_r};font-size:0.82rem;'>"
                    f"Length: {actual_len_r} chars (expected {expected_len})</span>",
                    unsafe_allow_html=True
                )

        if st.button("Compare Hashes", key="ic_compare", type="primary",
                     use_container_width=True):
            h1_raw = computed_hash_input.strip() if computed_hash_input else ""
            h2_raw = known_hash.strip() if known_hash else ""

            if not h1_raw:
                st.warning("Please paste a computed hash in the left field.")
            elif not h2_raw:
                st.warning("Please paste the official hash in the right field.")
            else:
                h1 = h1_raw.lower().replace(" ", "")
                h2 = h2_raw.lower().replace(" ", "")

                # Validate lengths for both inputs
                len_ok_h1 = len(h1) == expected_len
                len_ok_h2 = len(h2) == expected_len

                if not len_ok_h1 or not len_ok_h2:
                    issues = []
                    if not len_ok_h1:
                        issues.append(f"Computed hash is {len(h1)} chars")
                    if not len_ok_h2:
                        issues.append(f"Official hash is {len(h2)} chars")
                    st.markdown(
                        f"<div class='hash-nomatch'>⚠ Length mismatch for {ic_algo_name} "
                        f"(expected {expected_len} chars): {'; '.join(issues)}. "
                        f"Check the algorithm selection or the pasted values.</div>",
                        unsafe_allow_html=True
                    )
                elif h1 == h2:
                    st.markdown(
                        "<div class='hash-match'>"
                        "✔ Match — Hashes are identical. Integrity verified.</div>",
                        unsafe_allow_html=True
                    )
                else:
                    st.markdown(
                        "<div class='hash-nomatch'>"
                        "✖ Mismatch — Hashes differ. Content may be different or corrupted.</div>",
                        unsafe_allow_html=True
                    )
                    diff_count = sum(c1 != c2 for c1, c2 in zip(h1, h2))
                    st.markdown(
                        f"<span style='color:#4A6A8A;font-size:0.82rem;'>"
                        f"{diff_count} character(s) differ out of {len(h1)}</span>",
                        unsafe_allow_html=True
                    )

    # ── Tab 3: Hash Lookup ──────────────────────────────
    with tab3:
        st.markdown("**Check a file hash.**")
        st.markdown(
            "<div style='font-size:0.88rem;color:#4A6A8A;margin-bottom:14px;'>"
            "Supports MD5, SHA-1, and SHA-256 hashes. Hash Lookup will return whether "
            "the file was previously scanned and if it was flagged as malicious."
            "</div>",
            unsafe_allow_html=True
        )

        vt_hash_input = st.text_input(
            "File Hash (MD5 / SHA-1 / SHA-256)",
            placeholder="e.g. 44d88612fea8a8f36de82e1278abb02f  or a SHA-256 hash…",
            key="vt_hash_input"
        )

        if st.button("Check File Hash", key="vt_hash_check", type="primary", use_container_width=True):
            h = vt_hash_input.strip() if vt_hash_input else ""
            if not h:
                st.warning("Please enter a file hash to check.")
            elif not VT_API_KEY:
                st.error("❌ VirusTotal API key not configured. Add VT_API_KEY to your .env file.")
            else:
                with st.spinner("Querying VirusTotal…"):
                    try:
                        resp = requests.get(
                            f"https://www.virustotal.com/api/v3/files/{h}",
                            headers={"x-apikey": VT_API_KEY},
                            timeout=15
                        )
                        if resp.status_code == 401:
                            st.error("❌ VirusTotal: Invalid API key.")
                        elif resp.status_code == 404:
                            st.info("ℹ️ Hash not found in VirusTotal database. The file may never have been scanned.")
                        elif resp.status_code == 429:
                            st.warning("⚠️ VirusTotal rate limit exceeded. Please wait and try again.")
                        elif resp.status_code == 200:
                            data = resp.json().get("data", {}).get("attributes", {})
                            stats = data.get("last_analysis_stats", {})
                            malicious  = stats.get("malicious", 0)
                            suspicious = stats.get("suspicious", 0)
                            harmless   = stats.get("harmless", 0)
                            undetected = stats.get("undetected", 0)
                            total      = malicious + suspicious + harmless + undetected

                            if malicious > 0:
                                verdict_color  = "#C0392B"
                                verdict_bg     = "rgba(240,112,112,0.10)"
                                verdict_border = "#C0392B"
                                verdict_icon   = "🔴"
                                verdict_text   = f"MALICIOUS — Flagged by {malicious} engine(s)"
                            elif suspicious > 0:
                                verdict_color  = "#E87B00"
                                verdict_bg     = "rgba(245,200,66,0.10)"
                                verdict_border = "#E87B00"
                                verdict_icon   = "🟡"
                                verdict_text   = f"SUSPICIOUS — Flagged by {suspicious} engine(s)"
                            else:
                                verdict_color  = "#E87B00"
                                verdict_bg     = "rgba(232,123,0,0.10)"
                                verdict_border = "#E87B00"
                                verdict_icon   = "✅"
                                verdict_text   = "CLEAN — No engines flagged this file"

                            st.markdown(
                                f"<div style='background:{verdict_bg};border:1px solid {verdict_border};"
                                f"border-radius:10px;padding:14px 18px;margin:12px 0;"
                                f"color:{verdict_color};font-weight:700;font-size:1.05rem;text-align:center;'>"
                                f"{verdict_icon} {verdict_text}"
                                f"</div>",
                                unsafe_allow_html=True
                            )

                            col1, col2, col3, col4 = st.columns(4)
                            col1.metric("Malicious",  malicious)
                            col2.metric("Suspicious", suspicious)
                            col3.metric("Harmless",   harmless)
                            col4.metric("Undetected", undetected)

                            names = data.get("names", [])
                            file_name = data.get("meaningful_name") or (names[0] if names else "Unknown")
                            file_type = data.get("type_description", "N/A")
                            file_size = data.get("size")
                            size_str  = f"{file_size:,} bytes" if file_size else "N/A"

                            st.markdown("---")
                            st.markdown(
                                f"<div style='font-size:0.9rem;line-height:2;color:#0D3380;'>"
                                f"<b style='color:#4A6A8A;'>File Name:</b> {file_name}<br>"
                                f"<b style='color:#4A6A8A;'>File Type:</b> {file_type}<br>"
                                f"<b style='color:#4A6A8A;'>File Size:</b> {size_str}<br>"
                                f"<b style='color:#4A6A8A;'>Total Engines:</b> {total}"
                                f"</div>",
                                unsafe_allow_html=True
                            )

                            vt_url = f"https://www.virustotal.com/gui/file/{h}"
                            st.markdown(
                                f"<a href='{vt_url}' target='_blank' style='"
                                f"color:#0064B4;font-size:0.88rem;'>🔗 View full report on VirusTotal →</a>",
                                unsafe_allow_html=True
                            )
                        else:
                            st.error(f"Unexpected response from VirusTotal: HTTP {resp.status_code}")
                    except requests.exceptions.Timeout:
                        st.error("⏱ Request timed out. Please try again.")
                    except Exception as e:
                        st.error(f"Error querying VirusTotal: {e}")
