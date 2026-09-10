# snitch

defensive honey-file tripwire for **macOS** / **Linux**. Matrix-green TUI. Plants bait under `~/.snitch`, diffs tampering, kills the offending PID when it can, logs locally, pings Discord, and archives history to **Supabase** so the terminal stays clean.

> Lab / personal-defense use only. Auto-kill needs permission for the target PID.

## Setup

```bash
cd canary-edr
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

| Var | Purpose |
|-----|---------|
| `DISCORD_WEBHOOK_URL` | Optional Discord alerts |
| `SUPABASE_URL` | Your project API URL |
| `SUPABASE_KEY` | anon / publishable key |

### Supabase table (once)

1. Open Supabase → **SQL Editor**
2. Paste and run [`sql/snitch_events.sql`](sql/snitch_events.sql)
3. Confirm table `snitch_events` exists

Past events live in **Table Editor → snitch_events**. Sort by `created_at`, `action`, `file_name`, etc. Full diffs are in `content_diff`.

## Run

```bash
source .venv/bin/activate
python main.py
```

### TUI (kept lean)

- **status** — armed, bait path, kills, discord/supabase
- **live** — this session only (max ~8 rows); shows **DELETE!** or **MODIFY** + short change summary
- **archive peek** — last 5 rows from Supabase (`s` cycles sort incl. deletes)
- keys: **`s`** cycle sort · **`r`** refresh · **ctrl+c** quit

### What gets stored in Supabase

| Table | Role |
|-------|------|
| `snitch_events` | Every hit: before/after text, unified diff, `is_delete`, PID, action |
| `snitch_snapshots` | Live memory of each bait file — **updated on every modify**, marked deleted on delete |

Sort history in **Table Editor → snitch_events**. Check current bait contents in **snitch_snapshots**.

## Simulate

Second terminal:

```bash
echo "hack" >> ~/.snitch/passwords.txt
```

Or open `~/.snitch/passwords.txt` in Finder (**Go → Go to Folder…** → `/Users/YOU/.snitch`), edit, save.

Hold the file open to exercise kill attribution:

```bash
python3 -c "import time; f=open('$HOME/.snitch/passwords.txt','a'); f.write('probe\n'); f.flush(); time.sleep(10)"
```

## Notes

- Bait files are decoys in `~/.snitch` (not your real secrets).
- Old `~/.canary` from earlier builds is unused; safe to `rm -rf ~/.canary`.
- Diffs for text files show `+`/`-` line changes; binaries log size + short hashes.
- Do not commit `.env` or real webhook/keys.
