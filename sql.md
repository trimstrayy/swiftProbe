# SwiftProbe Supabase SQL

Run this whole script in the Supabase SQL editor for a fresh database.

It creates the required tables used by the current pipeline:

- `cases` — Case registry with owner
- `case_members` — Multi-investigator access control
- `target_artifacts` — Known-bad file hashes
- `files_recovered` — Carved/recovered file records
- `file_operations` — Pipeline run audit log
- `log_analysis_sessions` — Log analysis run metadata
- `log_events` — Individual parsed events
- `logon_sessions` — Reconstructed interactive logon sessions

It also enables row level security with proper policies:
- `cases` and `case_members` are restricted to the owning user
- `files_recovered` and `file_operations` are restricted to case members
- `target_artifacts` is globally readable but insert/update restricted to service role

```sql
create extension if not exists pgcrypto;

-- ── Cases table ──────────────────────────────────────────────────────────

create table if not exists public.cases (
    id uuid primary key default gen_random_uuid(),
    case_number text not null unique,
    title text,
    description text,
    owner_user_id uuid not null references auth.users(id) on delete cascade,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_cases_owner on public.cases (owner_user_id);
create index if not exists idx_cases_case_number on public.cases (case_number);

-- ── Case members join table ──────────────────────────────────────────────

create table if not exists public.case_members (
    id bigserial primary key,
    case_id uuid not null references public.cases(id) on delete cascade,
    user_id uuid not null references auth.users(id) on delete cascade,
    role text not null default 'investigator' check (role in ('owner', 'investigator', 'viewer')),
    created_at timestamptz not null default now(),
    unique (case_id, user_id)
);

create index if not exists idx_case_members_case on public.case_members (case_id);
create index if not exists idx_case_members_user on public.case_members (user_id);

-- ── Target artifacts (shared known-hash list) ────────────────────────────

create table if not exists public.target_artifacts (
    id bigserial primary key,
    filename text not null,
    expected_sha256 char(64) not null,
    description text,
    created_at timestamptz not null default now()
);

create index if not exists idx_target_artifacts_expected_sha256
    on public.target_artifacts (expected_sha256);

create index if not exists idx_target_artifacts_filename
    on public.target_artifacts (filename);

-- ── Files recovered (carved from evidence) ───────────────────────────────

create table if not exists public.files_recovered (
    id bigserial primary key,
    case_id uuid not null references public.cases(id) on delete cascade,
    filename text not null,
    actual_sha256 char(64) not null,
    physical_offset_bytes bigint not null default 0,
    file_size_bytes bigint not null default 0,
    match_found boolean not null default false,
    is_integrity_verified boolean not null default false,
    source_image_path text,
    source_image_sha256 char(64),
    source_image_size bigint,
    source_image_mtime text,
    carved_file_path text,
    carved_file_type text,
    carved_metadata_json jsonb,
    source_metadata_json jsonb,
    recovery_method text default 'signature_carving',
    created_at timestamptz not null default now()
);

create index if not exists idx_files_recovered_case_id
    on public.files_recovered (case_id);

create index if not exists idx_files_recovered_actual_sha256
    on public.files_recovered (actual_sha256);

-- ── File operations (pipeline audit log) ─────────────────────────────────

create table if not exists public.file_operations (
    id bigserial primary key,
    case_id uuid not null references public.cases(id) on delete cascade,
    operation_type text not null,
    source_image_path text not null,
    source_image_name text,
    source_image_sha256 char(64),
    source_image_size bigint,
    source_image_mtime text,
    output_dir text,
    carved_file_count bigint not null default 0,
    matched_file_count bigint not null default 0,
    source_metadata jsonb not null default '{}'::jsonb,
    carved_output jsonb not null default '[]'::jsonb,
    recovered_files jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now()
);

create index if not exists idx_file_operations_case_id
    on public.file_operations (case_id);

create index if not exists idx_file_operations_source_sha256
    on public.file_operations (source_image_sha256);

-- ── Log analysis tables ──────────────────────────────────────────────────

create table if not exists public.log_analysis_sessions (
    id bigserial primary key,
    case_id uuid references public.cases(id) on delete set null,
    analysis_source text,
    source_path text,
    source_filename text,
    source_sha256 text,
    source_size bigint,
    source_mtime text,
    logs_scanned jsonb default '[]'::jsonb,
    event_count bigint default 0,
    usb_connection_count bigint default 0,
    usb_mounted_count bigint default 0,
    usb_removed_count bigint default 0,
    file_transfer_started_count bigint default 0,
    file_transfer_completed_count bigint default 0,
    user_attribution_count bigint default 0,
    session_count bigint default 0,
    session_trace_source text,
    activity_counts jsonb default '{}'::jsonb,
    user_counts jsonb default '[]'::jsonb,
    summary jsonb default '{}'::jsonb,
    file_metadata jsonb default '{}'::jsonb,
    uploaded_event_count bigint default 0,
    uploaded_events jsonb default '[]'::jsonb,
    identified_users jsonb default '[]'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists public.log_events (
    id bigserial primary key,
    session_id bigint references public.log_analysis_sessions(id) on delete cascade,
    case_id uuid references public.cases(id) on delete set null,
    source_kind text,
    log_path text,
    record_id text,
    event_id bigint,
    provider text,
    channel text,
    computer text,
    timestamp text,
    activity_type text,
    activity_stage text,
    confidence real,
    user_name text,
    user_domain text,
    user_sid text,
    logon_id text,
    process_name text,
    activity_tags jsonb default '[]'::jsonb,
    indicators jsonb default '[]'::jsonb,
    summary text,
    event_data jsonb default '{}'::jsonb,
    user_data jsonb default '{}'::jsonb,
    system_data jsonb default '{}'::jsonb,
    user_context jsonb default '{}'::jsonb,
    raw_xml text,
    created_at timestamptz not null default now()
);

create table if not exists public.logon_sessions (
    id bigserial primary key,
    session_id bigint references public.log_analysis_sessions(id) on delete cascade,
    case_id uuid references public.cases(id) on delete set null,
    logon_id text,
    user_name text,
    user_domain text,
    logon_type text,
    logon_time text,
    logoff_time text,
    source text,
    attributed_usb_event_indicators jsonb default '[]'::jsonb,
    created_at timestamptz not null default now()
);

-- ── Row Level Security ───────────────────────────────────────────────────

alter table public.cases enable row level security;
alter table public.case_members enable row level security;
alter table public.target_artifacts enable row level security;
alter table public.files_recovered enable row level security;
alter table public.file_operations enable row level security;
alter table public.log_analysis_sessions enable row level security;
alter table public.log_events enable row level security;
alter table public.logon_sessions enable row level security;

-- Helper function: check if a user is a member of a case
create or replace function public.is_case_member(case_id uuid, user_id uuid)
returns boolean
language sql
stable
as $$
    select exists (
        select 1 from public.case_members
        where case_members.case_id = is_case_member.case_id
          and case_members.user_id = is_case_member.user_id
    );
$$;

-- ── Cases policies ───────────────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'cases' and policyname = 'cases_select_own') then
        create policy cases_select_own on public.cases
            for select using (owner_user_id = auth.uid() or public.is_case_member(id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'cases' and policyname = 'cases_insert_own') then
        create policy cases_insert_own on public.cases
            for insert with check (owner_user_id = auth.uid());
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'cases' and policyname = 'cases_update_own') then
        create policy cases_update_own on public.cases
            for update using (owner_user_id = auth.uid());
    end if;
end $$;

-- ── Case members policies ────────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'case_members' and policyname = 'case_members_select_own') then
        create policy case_members_select_own on public.case_members
            for select using (user_id = auth.uid() or public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'case_members' and policyname = 'case_members_insert_owner') then
        create policy case_members_insert_owner on public.case_members
            for insert with check (
                exists (select 1 from public.cases where id = case_id and owner_user_id = auth.uid())
            );
    end if;
end $$;

-- ── Target artifacts policies ─────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'target_artifacts' and policyname = 'target_artifacts_select_all') then
        create policy target_artifacts_select_all
            on public.target_artifacts for select using (true);
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'target_artifacts' and policyname = 'target_artifacts_insert_service') then
        create policy target_artifacts_insert_service
            on public.target_artifacts for insert
            with check (auth.role() = 'service_role');
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'target_artifacts' and policyname = 'target_artifacts_update_service') then
        create policy target_artifacts_update_service
            on public.target_artifacts for update
            using (auth.role() = 'service_role');
    end if;
end $$;

-- ── Files recovered policies ──────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'files_recovered' and policyname = 'files_recovered_select_member') then
        create policy files_recovered_select_member on public.files_recovered
            for select using (public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'files_recovered' and policyname = 'files_recovered_insert_member') then
        create policy files_recovered_insert_member on public.files_recovered
            for insert with check (public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

-- ── File operations policies ──────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'file_operations' and policyname = 'file_operations_select_member') then
        create policy file_operations_select_member on public.file_operations
            for select using (public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'file_operations' and policyname = 'file_operations_insert_member') then
        create policy file_operations_insert_member on public.file_operations
            for insert with check (public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

-- ── Log analysis policies ─────────────────────────────────────────────────

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'log_analysis_sessions' and policyname = 'log_analysis_sessions_select_member') then
        create policy log_analysis_sessions_select_member on public.log_analysis_sessions
            for select using (case_id is null or public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'log_events' and policyname = 'log_events_select_member') then
        create policy log_events_select_member on public.log_events
            for select using (case_id is null or public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

do $$
begin
    if not exists (select 1 from pg_policies where schemaname = 'public' and tablename = 'logon_sessions' and policyname = 'logon_sessions_select_member') then
        create policy logon_sessions_select_member on public.logon_sessions
            for select using (case_id is null or public.is_case_member(case_id, auth.uid()));
    end if;
end $$;

-- ── Seed data ─────────────────────────────────────────────────────────────

insert into public.target_artifacts (filename, expected_sha256, description)
values
    ('example_target_1.bin', '0000000000000000000000000000000000000000000000000000000000000000', 'Replace with a real target hash'),
    ('example_target_2.bin', '1111111111111111111111111111111111111111111111111111111111111111', 'Replace with a real target hash')
on conflict do nothing;
```

## Environment variables

Use these names in your local `.env` or deployment environment:

```bash
NEXT_PUBLIC_SUPABASE_URL=https://yqksremfthtpuxuormsv.supabase.co
NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY=your_publishable_key_here
```

The backend also accepts these fallback names if you prefer them:

```bash
SUPABASE_URL=...
SUPABASE_KEY=...
```

## Notes

- The SQL is safe to re-run (uses `create table if not exists` and `do $$ ... if not exists $$` guard patterns).
- `cases` and `case_members` provide proper multi-investigator access control.
- `target_artifacts` is globally readable but insert/update requires `service_role`.
- `files_recovered` and `file_operations` use `case_id` as a foreign key to `cases.id`.
- For development/testing, you can temporarily set permissive policies by replacing the member-check policies with `using (true)` / `with check (true)`.