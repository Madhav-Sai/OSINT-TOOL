import feedparser
import streamlit as st
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

RSS_FEEDS = {
    "BleepingComputer":  "https://www.bleepingcomputer.com/feed/",
    "The Hacker News":   "https://thehackernews.com/feeds/posts/default",
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
}

ARTICLES_PER_SOURCE = 10


def _parse_date(entry) -> datetime:
    for attr in ("published_parsed", "updated_parsed"):
        val = getattr(entry, attr, None)
        if val:
            try:
                return datetime(*val[:6])
            except Exception:
                pass
    return datetime.min


def _fetch_source(name_url):
    name, url = name_url
    articles = []
    try:
        feed = feedparser.parse(url)
        for entry in feed.entries[:ARTICLES_PER_SOURCE]:
            title = getattr(entry, "title", "").strip()
            link  = getattr(entry, "link",  "").strip()
            if title and link:
                articles.append({
                    "title":     title,
                    "source":    name,
                    "link":      link,
                    "published": _parse_date(entry),
                })
    except Exception:
        pass
    return articles


def get_cyber_news() -> list[dict]:
    articles = []
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {executor.submit(_fetch_source, item): item[0]
                   for item in RSS_FEEDS.items()}
        for future in as_completed(futures):
            try:
                articles.extend(future.result())
            except Exception:
                pass
    articles.sort(key=lambda a: a["published"], reverse=True)
    return articles

def render_cyber_news():
    st.markdown("""
<div class='osint-header' style='margin-bottom:8px;'>
    <h1 style='font-size:1.7rem;'>Live Cybersecurity News</h1>
    <p>Aggregated from BleepingComputer · The Hacker News · Krebs on Security</p>
</div>
""", unsafe_allow_html=True)

    # ── Source filter chips ──────────────────────────────────
    all_sources = ["All"] + list(RSS_FEEDS.keys())
    source_filter = st.pills(
        "Source",
        all_sources,
        default="All",
        key="news_source_filter",
    )

    # ── Keyword filter ───────────────────────────────────────
    keyword = st.text_input(
        "Filter by keyword",
        placeholder="e.g.  ransomware  ·  CVE  ·  zero-day",
        key="news_keyword",
    )

    with st.spinner("Fetching latest news…"):
        articles = get_cyber_news()

    if not articles:
        st.warning("Could not fetch news at this time. Check your internet connection.")
        return

    # Apply filters
    if source_filter and source_filter != "All":
        articles = [a for a in articles if a["source"] == source_filter]

    if keyword.strip():
        kw = keyword.strip().lower()
        articles = [a for a in articles if kw in a["title"].lower()]

    if not articles:
        st.info("No articles match your filters.")
        return

    # ── Source badge colours — matching theme ────────────────
    SOURCE_COLORS = {
        "BleepingComputer":  "#0064B4",
        "The Hacker News":   "#003C8C",
        "Krebs on Security": "#E87B00",
    }

    st.markdown(
        f"<p style='color:#4A6A8A;font-size:0.85rem;margin-bottom:12px;'>"
        f"Showing <b style='color:#0D3380;'>{len(articles)}</b> articles</p>",
        unsafe_allow_html=True,
    )

    for article in articles:
        badge_color = SOURCE_COLORS.get(article["source"], "#0064B4")
        pub_str = ""
        if article["published"] != datetime.min:
            pub_str = article["published"].strftime("%d %b %Y").lstrip("0")

        st.markdown(f"""
<div class='card' style='border-left:3px solid {badge_color};margin-bottom:10px;'>
  <div style='display:flex;align-items:center;gap:10px;margin-bottom:6px;flex-wrap:wrap;'>
    <span style='background:{badge_color}18;color:{badge_color};border:1px solid {badge_color}44;
                 font-size:0.72rem;font-weight:700;padding:2px 10px;border-radius:999px;
                 white-space:nowrap;letter-spacing:0.4px;'>
      {article["source"]}
    </span>
    {f'<span style="color:#4A6A8A;font-size:0.78rem;">{pub_str}</span>' if pub_str else ''}
  </div>
  <div style='color:#0D3380;font-weight:600;font-size:0.97rem;line-height:1.45;margin-bottom:8px;'>
    {article["title"]}
  </div>
  <a href='{article["link"]}' target='_blank'
     style='color:#0064B4;font-size:0.82rem;text-decoration:none;font-weight:500;'>
    Read More →
  </a>
</div>
""", unsafe_allow_html=True)

    # ── Footer note ──────────────────────────────────────────
    st.markdown("""
<div style='margin-top:24px;font-size:0.78rem;color:#4A6A8A;text-align:center;'>
  News sourced directly from RSS feeds · Refresh the page for the latest updates
</div>
""", unsafe_allow_html=True)
