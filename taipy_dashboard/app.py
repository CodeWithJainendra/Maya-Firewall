import random
import os
from datetime import datetime

import pandas as pd
import requests
from taipy.gui import Gui


def env_first(*names, default=None):
    for name in names:
        value = os.getenv(name)
        if value is not None and value != "":
            return value
    return default


def env_bool(*names, default=False):
    raw = env_first(*names)
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def env_float(*names, default=2.0):
    raw = env_first(*names)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def env_int(*names, default):
    raw = env_first(*names)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


API_BASE = env_first("MAYA_TAIPY_API_BASE", "MAYA_API_BASE", default="http://127.0.0.1:8900")
DASHBOARD_TOKEN = env_first("MAYA_TAIPY_DASHBOARD_TOKEN", "MAYA_DASHBOARD_TOKEN")
REQUEST_TIMEOUT_SECS = env_float("MAYA_TAIPY_REQUEST_TIMEOUT_SECS", default=2.0)
TAIPY_HOST = env_first("MAYA_TAIPY_HOST", default="127.0.0.1")
TAIPY_PORT = env_int("MAYA_TAIPY_PORT", default=5000)
TAIPY_DARK_MODE = env_bool("MAYA_TAIPY_DARK_MODE", default=True)
TAIPY_RELOADER = env_bool("MAYA_TAIPY_RELOADER", default=True)


def request_headers():
    if DASHBOARD_TOKEN:
        return {"x-maya-dashboard-token": DASHBOARD_TOKEN}
    return {}


def get_stats():
    try:
        response = requests.get(
            f"{API_BASE}/api/stats",
            timeout=REQUEST_TIMEOUT_SECS,
            headers=request_headers(),
        )
        response.raise_for_status()
        return response.json(), True
    except Exception:
        return {
            "active_decoys": None,
            "active_sessions": None,
            "trapped_attackers": None,
            "malware_captured": None,
            "scans_detected": None,
            "alerts_generated": None,
        }, False


def seed_series():
    labels = ["10:00", "10:15", "10:30", "10:45", "11:00", "11:15", "11:30"]
    points = [45, 52, 38, 85, 65, 92, 78]
    return pd.DataFrame({"time": labels, "intensity": points})


def make_breakdown(stats):
    metrics = [
        ("Active Decoys", stats["active_decoys"]),
        ("Active Sessions", stats["active_sessions"]),
        ("Trapped Attackers", stats["trapped_attackers"]),
        ("Malware Captured", stats["malware_captured"]),
        ("Alerts", stats["alerts_generated"]),
    ]

    rows = [metric for metric in metrics if metric[1] is not None]

    if not rows:
        return pd.DataFrame({"metric": [], "value": []})

    return pd.DataFrame(
        {
            "metric": [label for label, _ in rows],
            "value": [value for _, value in rows],
        }
    )


def display_counter(value):
    if value is None:
        return "Data unavailable"
    return value


stats, backend_available = get_stats()
attack_df = seed_series()
breakdown_df = make_breakdown(stats)

active_decoys = display_counter(stats["active_decoys"])
active_sessions = display_counter(stats["active_sessions"])
trapped_attackers = display_counter(stats["trapped_attackers"])
malware_captured = display_counter(stats["malware_captured"])
scans_detected = display_counter(stats["scans_detected"])
alerts_generated = display_counter(stats["alerts_generated"])
backend_status = "Connected" if backend_available else "Data unavailable (backend unreachable)"
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
<|{backend_status}|text|label=Backend Status|>
|>

<|{last_refresh}|text|label=Last Refresh|>

<|Refresh from MAYA API|button|on_action=refresh_data|>
"""


def refresh_data(state):
    latest, available = get_stats()

    state.active_decoys = display_counter(latest["active_decoys"])
    state.active_sessions = display_counter(latest["active_sessions"])
    state.trapped_attackers = display_counter(latest["trapped_attackers"])
    state.malware_captured = display_counter(latest["malware_captured"])
    state.scans_detected = display_counter(latest["scans_detected"])
    state.alerts_generated = display_counter(latest["alerts_generated"])
    state.backend_status = "Connected" if available else "Data unavailable (backend unreachable)"

    jitter = random.randint(-8, 10)
    updated_series = attack_df.copy()
    updated_series.loc[len(updated_series) - 1, "intensity"] = max(
        5, int(updated_series.iloc[-1]["intensity"]) + jitter
    )
    state.attack_df = updated_series

    state.breakdown_df = make_breakdown(latest)
    state.last_refresh = datetime.utcnow().strftime("%H:%M:%S UTC")


if __name__ == "__main__":
    Gui(page=page).run(
        title="MAYA Taipy Dashboard",
        dark_mode=TAIPY_DARK_MODE,
        use_reloader=TAIPY_RELOADER,
        host=TAIPY_HOST,
        port=TAIPY_PORT,
    )
