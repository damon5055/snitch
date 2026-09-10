# Canary EDR Tripwire

Defensive honey-file tripwire for **macOS** and **Linux**. It plants bait files under `~/.canary`, watches them with `watchdog`, attributes tampering via `lsof`, kills the offending process with `psutil`, logs to `security.log`, and optionally posts a Discord embed alert.

> Lab / personal-defense use only. Process termination requires sufficient privileges for the target PID. Do not run against production systems without understanding the kill behavior.

## Requirements

- Python 3.9+
- `lsof` on `PATH` (preinstalled on macOS; install via your package manager on Linux)
- Dependencies in `requirements.txt`

```bash
cd canary-edr
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Discord webhook setup (optional)

1. In Discord: **Server Settings → Integrations → Webhooks → New Webhook**.
2. Choose a channel, copy the webhook URL.
3. Export it before starting the tool:

```bash
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/ID/TOKEN"
```

If unset, local logging and process kill still work; Discord posts are skipped.

## Run

```bash
python main.py
```

You should see a Rich dashboard with:

- **Status** — `EDR Tripwire Active` and monitored file count  
- **Live Event Log** — reads/writes/blocks as a streaming table  
- **System Stats** — CPU / memory for the canary process  

Press **Ctrl+C** to stop cleanly.

Honey files are created once under:

| Path | Role |
|------|------|
| `~/.canary/passwords.txt` | Credential bait |
| `~/.canary/financials.docx` | Document bait |
| `~/.canary/private_keys.pem` | Key bait |

## Safe attack simulation

With the tripwire running, open a **second terminal** and append to a honey file:

```bash
echo "hack" >> ~/.canary/passwords.txt
```

Or delete one:

```bash
rm ~/.canary/private_keys.pem
```

Expected behavior:

1. The TUI **Live Event Log** shows `MODIFIED` / `DELETED`.
2. If `lsof` can attribute an open PID, that process is killed and the row shows `KILLED`.
3. `security.log` records the full event.
4. If `DISCORD_WEBHOOK_URL` is set, Discord receives an embed titled **🛑 Ransomware Attack Neutralized**.

**Notes for simulation:** short-lived shells (`echo >> file`) often exit before `lsof` runs, so you may see `unattributed` / `LOGGED` instead of a kill. To exercise attribution, hold the file open longer, e.g.:

```bash
# keeps the file open ~10s while you watch the dashboard
python3 -c "import time; f=open('$HOME/.canary/passwords.txt','a'); f.write('probe\n'); f.flush(); time.sleep(10)"
```

Re-run `python main.py` after deletion tests — missing honey files are recreated on startup.

## Privacy

- Do not commit real Discord webhook URLs.
- `security.log` may contain process command lines; treat it as sensitive.
