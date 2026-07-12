# SwiftProbe Supabase SQL

Run this whole script in the Supabase SQL editor for a fresh database.

It creates the required tables used by the current pipeline:

- `target_artifacts`
- `files_recovered`
- `file_operations`

It also enables row level security and adds permissive policies for testing with the publishable key.

```sql
create extension if not exists pgcrypto;

create table if not exists public.target_artifacts (
    filename text not null,
    expected_sha256 char(64) not null,
    description text
);

create table if not exists public.files_recovered (
    case_id text not null,
    filename text not null,
    actual_sha256 char(64) not null,
    physical_offset_bytes bigint not null default 0,
    file_size_bytes bigint not null default 0,
    match_found boolean not null default false,
<<<<<<< HEAD
    is_integrity_verified boolean not null default false
=======
    source_image_path text,
    source_image_sha256 char(64),
    source_image_size bigint,
    source_image_mtime text,
    carved_file_path text,
    carved_file_type text,
    carved_metadata_json jsonb,
    source_metadata_json jsonb
);

create table if not exists public.file_operations (
    id bigserial primary key,
    case_id text not null,
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
>>>>>>> 8ea45fae87b25e4c91247daebe70489098d4c75a
);

create index if not exists idx_target_artifacts_expected_sha256
    on public.target_artifacts (expected_sha256);

create index if not exists idx_target_artifacts_filename
    on public.target_artifacts (filename);

create index if not exists idx_files_recovered_case_id
    on public.files_recovered (case_id);

create index if not exists idx_files_recovered_actual_sha256
    on public.files_recovered (actual_sha256);

create index if not exists idx_file_operations_case_id
    on public.file_operations (case_id);

create index if not exists idx_file_operations_source_sha256
    on public.file_operations (source_image_sha256);

alter table public.target_artifacts enable row level security;
alter table public.files_recovered enable row level security;
alter table public.file_operations enable row level security;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'target_artifacts'
          and policyname = 'target_artifacts_select_all'
    ) then
        create policy target_artifacts_select_all
        on public.target_artifacts
        for select
        using (true);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'file_operations'
          and policyname = 'file_operations_select_all'
    ) then
        create policy file_operations_select_all
        on public.file_operations
        for select
        using (true);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'file_operations'
          and policyname = 'file_operations_insert_all'
    ) then
        create policy file_operations_insert_all
        on public.file_operations
        for insert
        with check (true);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'files_recovered'
          and policyname = 'files_recovered_select_all'
    ) then
        create policy files_recovered_select_all
        on public.files_recovered
        for select
        using (true);
    end if;
end
$$;

do $$
begin
    if not exists (
        select 1 from pg_policies
        where schemaname = 'public'
          and tablename = 'files_recovered'
          and policyname = 'files_recovered_insert_all'
    ) then
        create policy files_recovered_insert_all
        on public.files_recovered
        for insert
        with check (true);
    end if;
end
$$;

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

- The SQL is intentionally permissive so you can test quickly with the publishable key.
- For production, tighten the RLS policies to authenticated users or a service-role backend.
- The pipeline currently reads from `target_artifacts` and writes to `files_recovered` and `file_operations` using the exact column names above.