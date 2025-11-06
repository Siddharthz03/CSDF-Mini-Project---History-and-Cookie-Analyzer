
"""
History & Cookie Analyzer + Safety Detection + Visualization
"""

import os
import shutil
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
import pandas as pd
import matplotlib.pyplot as plt
import argparse
import sys

SUSPICIOUS_TLDS = ["xyz", "top", "click", "monster", "cyou", "shop", "fit"]
PHISHING_WORDS = ["login", "verify", "secure", "reset", "bank", "account"]
PIRACY_WORDS = ["crack", "torrent", "keygen", "serial"]
ADULT_WORDS = ["porn", "xxx", "adult"]

def chrome_user_data_dir():
    home = Path.home()
    system = sys.platform
    if system == "darwin":
        return home / "Library" / "Application Support" / "Google" / "Chrome"
    elif system.startswith("win"):
        return Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data"
    else:
        return home / ".config" / "google-chrome"

def find_profile_dir(base_dir):
    for pref in ["Default", "Profile 1", "Profile 2"]:
        p = base_dir / pref
        if (p / "History").exists():
            return p

    if base_dir.exists():
        for p in base_dir.iterdir():
            if (p / "History").exists():
                return p
    return None


def evaluate_safety(df):
    risk_score = 0
    risky_sites = []

    for url in df["url"].dropna():
        domain = url.lower()

        if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            risk_score += 2
            risky_sites.append(url)

        if any(kw in domain for kw in PHISHING_WORDS):
            risk_score += 5
            risky_sites.append(url)

        if any(kw in domain for kw in PIRACY_WORDS):
            risk_score += 3
            risky_sites.append(url)

        if any(kw in domain for kw in ADULT_WORDS):
            risk_score += 3
            risky_sites.append(url)

    if risk_score == 0:
        status = "SAFE ✅"
    elif risk_score <= 5:
        status = "MODERATE RISK ⚠️"
    else:
        status = "HIGH RISK ❌"

    return status, list(set(risky_sites)), risk_score

def safe_copy(src_path: Path, dst_dir: Path):
    dst_dir.mkdir(parents=True, exist_ok=True)
    dst = dst_dir / ("copy_" + src_path.name)
    shutil.copy2(src_path, dst)
    return dst

def chrome_time_to_dt(chrome_time):
    try:
        if chrome_time is None or chrome_time == 0:
            return None
        return datetime(1601,1,1) + timedelta(microseconds=int(chrome_time))
    except:
        return None


def extract_history(history_db_path):
    conn = sqlite3.connect(history_db_path)
    df = pd.read_sql_query("SELECT url, title, visit_count, last_visit_time FROM urls;", conn)
    conn.close()
    df['last_visit_time'] = df['last_visit_time'].apply(chrome_time_to_dt)
    df = df.dropna(subset=['url']).reset_index(drop=True)
    return df


def extract_cookies(cookies_db_path):
    conn = sqlite3.connect(cookies_db_path)
    df = pd.read_sql_query("SELECT host_key, name, value, creation_utc, expires_utc FROM cookies;", conn)
    conn.close()
    df['creation_utc'] = df['creation_utc'].apply(chrome_time_to_dt)
    df['expires_utc'] = df['expires_utc'].apply(chrome_time_to_dt)
    return df


def show_top_sites(df, top_n=10):
    domain_series = df['url'].str.extract(r'^(?:https?://)?(?:www\.)?([^/]+)')[0].fillna('unknown')
    counts = domain_series.value_counts().head(top_n)
    print("\nTop {} visited domains:".format(top_n))
    for i,(dom,cnt) in enumerate(counts.items(), start=1):
        print(f"{i}. {dom} — {cnt} visits")

def show_recent_visits(df, limit=10):
    recent = df.sort_values('last_visit_time', ascending=False).head(limit)
    print("\nRecent visits:")
    for _, row in recent.iterrows():
        t = row['last_visit_time']
        ts = t.strftime("%Y-%m-%d %H:%M:%S") if t else "unknown"
        print(f"- {ts} | {row['url']} (visits: {row['visit_count']})")

def export_csv(df_history, df_cookies, out_dir: Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    df_history.to_csv(out_dir/"browser_history_report.csv", index=False)
    df_cookies.to_csv(out_dir/"browser_cookies_report.csv", index=False)
    print(f"\nReports saved to: {out_dir}")


def visualize_data(df_hist, score):
    # Top domain bar chart
    domain_series = df_hist['url'].str.extract(r'^(?:https?://)?(?:www\.)?([^/]+)')[0].fillna('unknown')
    counts = domain_series.value_counts().head(8)

    plt.figure()
    counts.plot(kind='bar')
    plt.title("Top 8 Most Visited Domains")
    plt.xlabel("Domain")
    plt.ylabel("Visit Count")
    plt.tight_layout()
    plt.show()

    
    labels = ["Safe", "Moderate Risk", "High Risk"]
    if score == 0:
        values = [1,0,0]
    elif score <= 5:
        values = [0,1,0]
    else:
        values = [0,0,1]

    plt.figure()
    plt.pie(values, labels=labels, autopct='%1.1f%%')
    plt.title("Browsing Safety Status")
    plt.show()


def main(args):
    global df_hist, score  
    base = chrome_user_data_dir()
    profile = find_profile_dir(base)

    if profile is None:
        print("Chrome profile not found at", base)
        return

    print("Profile found:", profile)

    tmp_dir = Path.cwd() / "tmp_dbs"
    history_src = profile / "History"
    cookies_src = profile / "Cookies"

    history_copy = safe_copy(history_src, tmp_dir)
    print("History copied:", history_copy)
    df_hist = extract_history(str(history_copy))

    if cookies_src.exists():
        cookies_copy = safe_copy(cookies_src, tmp_dir)
        df_cookies = extract_cookies(str(cookies_copy))
        print("Cookies copied:", cookies_copy)
    else:
        print("Cookies DB not found")
        df_cookies = pd.DataFrame()

    show_recent_visits(df_hist, limit=args.recent)
    show_top_sites(df_hist, top_n=args.top)

    status, risky_sites, score = evaluate_safety(df_hist)

    print("\n========= USER SAFETY REPORT =========")
    print(f"Browsing Risk Score: {score}")
    print(f"Overall Safety Status: {status}")

    if risky_sites:
        print("\n⚠️ Potentially Risky Sites Visited:")
        for s in risky_sites[:10]:
            print(" -", s)
    else:
        print("✅ No risky sites detected")

    print("======================================\n")

    export_csv(df_hist, df_cookies, Path.cwd() / "reports")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="History & Cookie Analyzer")
    parser.add_argument("--top", type=int, default=8)
    parser.add_argument("--recent", type=int, default=10)
    args = parser.parse_args()

    main(args)

    try:
        visualize_data(df_hist, score)
    except:
        print("Visualization skipped (no history loaded)")













        # /usr/bin/env python3 "/Users/siddharthzende/Desktop/SEM 7 Mini Projects /CSDF/analyzer.py"