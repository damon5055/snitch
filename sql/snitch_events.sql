-- snitch: events + live file snapshots
-- Run in Supabase → SQL Editor (safe to re-run)

-- Event history (what happened)
create table if not exists public.snitch_events (
  id uuid primary key default gen_random_uuid(),
  created_at timestamptz not null default now(),
  host text,
  event_type text not null,
  change_kind text,
  file_name text not null,
  file_path text,
  pid text,
  process_info text,
  action text not null,
  diff_summary text,
  content_diff text,
  before_content text,
  after_content text,
  is_delete boolean default false
);

alter table public.snitch_events add column if not exists change_kind text;
alter table public.snitch_events add column if not exists before_content text;
alter table public.snitch_events add column if not exists after_content text;
alter table public.snitch_events add column if not exists is_delete boolean default false;

create index if not exists snitch_events_created_at_idx
  on public.snitch_events (created_at desc);
create index if not exists snitch_events_action_idx
  on public.snitch_events (action);
create index if not exists snitch_events_file_name_idx
  on public.snitch_events (file_name);
create index if not exists snitch_events_is_delete_idx
  on public.snitch_events (is_delete);

alter table public.snitch_events enable row level security;

drop policy if exists "snitch_insert" on public.snitch_events;
drop policy if exists "snitch_select" on public.snitch_events;

create policy "snitch_insert"
  on public.snitch_events for insert to anon, authenticated
  with check (true);

create policy "snitch_select"
  on public.snitch_events for select to anon, authenticated
  using (true);

-- Live remembered content per bait file (updated on every modify)
create table if not exists public.snitch_snapshots (
  id uuid primary key default gen_random_uuid(),
  host text not null,
  file_name text not null,
  file_path text,
  content text,
  content_sha text,
  byte_size integer default 0,
  is_deleted boolean not null default false,
  updated_at timestamptz not null default now(),
  unique (host, file_name)
);

create index if not exists snitch_snapshots_updated_at_idx
  on public.snitch_snapshots (updated_at desc);

alter table public.snitch_snapshots enable row level security;

drop policy if exists "snitch_snap_insert" on public.snitch_snapshots;
drop policy if exists "snitch_snap_select" on public.snitch_snapshots;
drop policy if exists "snitch_snap_update" on public.snitch_snapshots;

create policy "snitch_snap_insert"
  on public.snitch_snapshots for insert to anon, authenticated
  with check (true);

create policy "snitch_snap_select"
  on public.snitch_snapshots for select to anon, authenticated
  using (true);

create policy "snitch_snap_update"
  on public.snitch_snapshots for update to anon, authenticated
  using (true)
  with check (true);
