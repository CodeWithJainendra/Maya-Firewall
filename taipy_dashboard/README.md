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

### Standardized environment variables

| Variable | Default | Purpose |
|---|---|---|
| `MAYA_TAIPY_API_BASE` | `http://127.0.0.1:8900` | Base URL for MAYA dashboard API |
| `MAYA_TAIPY_DASHBOARD_TOKEN` | unset | Dashboard auth token sent as `x-maya-dashboard-token` |
| `MAYA_TAIPY_REQUEST_TIMEOUT_SECS` | `2.0` | HTTP timeout for API requests |
| `MAYA_TAIPY_HOST` | `127.0.0.1` | Taipy bind host |
| `MAYA_TAIPY_PORT` | `5000` | Taipy bind port |
| `MAYA_TAIPY_DARK_MODE` | `true` | Taipy dark mode toggle |
| `MAYA_TAIPY_RELOADER` | `true` | Enable Taipy autoreload |

Backward compatibility aliases are supported:

- `MAYA_API_BASE` → `MAYA_TAIPY_API_BASE`
- `MAYA_DASHBOARD_TOKEN` → `MAYA_TAIPY_DASHBOARD_TOKEN`

## Deployment-friendly launcher

Use the standardized launcher script from workspace root:

```bash
./scripts/run-taipy-dashboard.sh
```

Example with explicit runtime config:

```bash
MAYA_TAIPY_API_BASE="http://maya-soc.internal:8900" \
MAYA_TAIPY_DASHBOARD_TOKEN="<token>" \
MAYA_TAIPY_HOST="0.0.0.0" \
MAYA_TAIPY_PORT="5050" \
MAYA_TAIPY_RELOADER="false" \
./scripts/run-taipy-dashboard.sh
```

Taipy UI opens locally and can refresh values from:

- `http://127.0.0.1:8900/api/stats`

If MAYA backend is not running, it falls back to demo values.
