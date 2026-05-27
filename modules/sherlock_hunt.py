import subprocess
import streamlit as st


def render_sherlock(username: str):
    st.subheader("Sherlock — Social Media Username Hunt")

    if st.session_state.sherlock_username != username:
        st.session_state.sherlock_username = username
        st.session_state.sherlock_results = []
        st.session_state.sherlock_scanning = True
        st.session_state.sherlock_stop_requested = False

    status_container  = st.empty()
    metrics_container = st.empty()
    results_container = st.empty()
    button_container  = st.empty()

    if st.session_state.sherlock_scanning:
        if button_container.button("🛑 Stop Scan", key="stop_sherlock",
                                   use_container_width=True, type="primary"):
            st.session_state.sherlock_stop_requested = True
            st.session_state.sherlock_scanning = False
            st.rerun()

        try:
            proc = subprocess.Popen(
                ["sherlock", username, "--print-found", "--no-color", "--timeout", "30"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )
            status_container.info("Scanning in real-time…")

            for line in proc.stdout:
                if st.session_state.sherlock_stop_requested:
                    proc.terminate()
                    proc.wait(timeout=3)
                    status_container.warning("⚠️ Scan stopped by user")
                    break

                line = line.strip()
                if line.startswith("[+]"):
                    try:
                        rest = line[3:].strip()
                        if ":" in rest:
                            site, url = rest.split(":", 1)
                            st.session_state.sherlock_results.append({
                                "site": site.strip(), "url": url.strip()
                            })
                            count = len(st.session_state.sherlock_results)
                            with metrics_container.container():
                                c1, c2 = st.columns(2)
                                c1.metric("Accounts Found", count)
                                c2.metric("Scanning", "400+ platforms")
                            with results_container.container():
                                st.markdown(f"#### {count} account(s) found:")
                                for h in st.session_state.sherlock_results:
                                    st.markdown(f"""
                                    <div class="sherlock-hit">
                                        <span class="sh-badge">FOUND</span>
                                        <span class="sh-site">{h['site']}</span>
                                        <span class="sh-url"><a href="{h['url']}" target="_blank">{h['url']}</a></span>
                                    </div>""", unsafe_allow_html=True)
                    except Exception:
                        continue

            proc.wait()
            st.session_state.sherlock_scanning = False

            if st.session_state.sherlock_stop_requested:
                status_container.warning("⚠️ Scan stopped by user")
            else:
                status_container.success(
                    f"✅ Scan completed! Found {len(st.session_state.sherlock_results)} accounts."
                )
        except FileNotFoundError:
            status_container.error("❌ Sherlock not found. Install: pip install sherlock-project")
            st.session_state.sherlock_scanning = False
        except Exception as e:
            status_container.error(f"❌ Error: {e}")
            st.session_state.sherlock_scanning = False

    elif not st.session_state.sherlock_scanning and st.session_state.sherlock_results:
        count = len(st.session_state.sherlock_results)
        with metrics_container.container():
            c1, c2 = st.columns(2)
            c1.metric("Total Accounts Found", count)
            c2.metric("Platforms Scanned", "400+")
        with results_container.container():
            st.markdown(f"#### All {count} account(s):")
            for h in st.session_state.sherlock_results:
                st.markdown(f"""
                <div class="sherlock-hit">
                    <span class="sh-badge">FOUND</span>
                    <span class="sh-site">{h['site']}</span>
                    <span class="sh-url"><a href="{h['url']}" target="_blank">{h['url']}</a></span>
                </div>""", unsafe_allow_html=True)
        button_container.success("✅ All results displayed")
    else:
        status_container.info("ℹ️ No accounts found for this username")
