import random
import os
from datetime import datetime

import pandas as pd
import requests
from taipy.gui import Gui

API_BASE = os.getenv("MAYA_API_BASE", "http://127.0.0.1:8900")
DASHBOARD_TOKEN = os.getenv("MAYA_DASHBOARD_TOKEN")


def request_headers():
    if DASHBOARD_TOKEN:
        return {"x-maya-dashboard-token": DASHBOARD_TOKEN}
    return {}


def get_stats():
    try:
        response = requests.get(
            f"{API_BASE}/api/stats",
            timeout=2,
            headers=request_headers(),
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return {
            "active_decoys": 512,
            "active_sessions": 8,
            "trapped_attackers": 8,
            "malware_captured": 142,
            "scans_detected": 2_400_000,
            "alerts_generated": 31,
        }


def seed_series():
    labels = ["10:00", "10:15", "10:30", "10:45", "11:00", "11:15", "11:30"]
    points = [45, 52, 38, 85, 65, 92, 78]
    return pd.DataFrame({"time": labels, "intensity": points})


def make_breakdown(stats):
    return pd.DataFrame(
        {
            "metric": [
                "Active Decoys",
                "Active Sessions",
                "Trapped Attackers",
                "Malware Captured",
                "Alerts",
            ],
            "value": [
                stats["active_decoys"],
                stats["active_sessions"],
                stats["trapped_attackers"],
                stats["malware_captured"],
                stats["alerts_generated"],
            ],
        }
    )


stats = get_stats()
attack_df = seed_series()
breakdown_df = make_breakdown(stats)

active_decoys = stats["active_decoys"]
active_sessions = stats["active_sessions"]
trapped_attackers = stats["trapped_attackers"]
malware_captured = stats["malware_captured"]
scans_detected = stats["scans_detected"]
alerts_generated = stats["alerts_generated"]
last_refresh = datetime.utcnow().strftime("%H:%M:%S UTC")


page = """
# MAYA - Taipy SOC View

<|layout|columns=1 1 1 1|
<|{active_decoys}|text|label=Active Decoys|class_name=card|>
<|{active_sessions}|text|label=Active Sessions|class_name=card|>
<|{trapped_attackers}|text|label=Trapped Attackers|class_name=card|>
<|{malware_captured}|text|label=Malware Captured|class_name=card|>
|>

<|layout|columns=1 1|
<|{attack_df}|chart|type=line|x=time|y=intensity|title=Attack Intensity Trend|height=300px|>
<|{breakdown_df}|chart|type=bar|x=metric|y=value|title=Current Grid Metrics|height=300px|>
|>

<|layout|columns=1 1 1|
<|{scans_detected}|text|label=Total Scans Detected|>
<|{alerts_generated}|text|label=Alerts Generated|>
<|{last_refresh}|text|label=Last Refresh|>
|>

<|Refresh from MAYA API|button|on_action=refresh_data|>
"""


def refresh_data(state):
    latest = get_stats()

    state.active_decoys = latest["active_decoys"]
    state.active_sessions = latest["active_sessions"]
    state.trapped_attackers = latest["trapped_attackers"]
    state.malware_captured = latest["malware_captured"]
    state.scans_detected = latest["scans_detected"]
    state.alerts_generated = latest["alerts_generated"]

    jitter = random.randint(-8, 10)
    updated_series = attack_df.copy()
    updated_series.loc[len(updated_series) - 1, "intensity"] = max(
        5, int(updated_series.iloc[-1]["intensity"]) + jitter
    )
    state.attack_df = updated_series

    state.breakdown_df = make_breakdown(latest)
    state.last_refresh = datetime.utcnow().strftime("%H:%M:%S UTC")


if __name__ == "__main__":
    Gui(page=page).run(title="MAYA Taipy Dashboard", dark_mode=True, use_reloader=True)
