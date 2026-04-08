# MAYA Taipy Dashboard

Lightweight Taipy-based graphical dashboard for MAYA stats.

## Setup

```bash
cd taipy_dashboard
python3 -m pip install -r requirements.txt
```

## Run

```bash
python3 app.py
```

Taipy UI opens locally and can refresh values from:

- `http://127.0.0.1:8900/api/stats`

If MAYA backend is not running, it falls back to demo values.
