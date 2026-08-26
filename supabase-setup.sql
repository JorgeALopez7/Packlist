-- PackList — run this once in Supabase → SQL Editor → New query → Run.
-- Creates the tables, locks them to their owner, and sets up photo storage.

-- ============================================================ TABLES

create table if not exists public.projects (
  id          text primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  name        text not null default '',
  short       text not null default '',
  sub         text not null default '',
  date        text not null default '',
  status      text not null default 'In progress',
  cats        jsonb not null default '{}'::jsonb,
  cover       jsonb,
  updated_at  timestamptz not null default now()
);

create table if not exists public.items (
  id          text primary key,
  user_id     uuid not null references auth.users(id) on delete cascade,
  pid         text not null,
  name        text not null default '',
  cat         text not null default '',
  sub         text not null default '',
  status      text not null default 'To Pack',
  qty         integer not null default 1,
  notes       text not null default '',
  keep        boolean not null default false,
  photo       jsonb,
  updated_at  timestamptz not null default now()
);

create table if not exists public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text not null default '',
  updated_at  timestamptz not null default now()
);

create index if not exists items_user_idx on public.items (user_id);
create index if not exists items_pid_idx  on public.items (pid);
create index if not exists projects_user_idx on public.projects (user_id);

-- ============================================================ ROW LEVEL SECURITY
-- Without this, the anon key would let anyone read everyone's data.
-- These policies make the database enforce ownership on every single query.

alter table public.projects enable row level security;
alter table public.items    enable row level security;
alter table public.profiles enable row level security;

drop policy if exists "own projects" on public.projects;
create policy "own projects" on public.projects
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "own items" on public.items;
create policy "own items" on public.items
  for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "own profile" on public.profiles;
create policy "own profile" on public.profiles
  for all using (auth.uid() = id) with check (auth.uid() = id);

-- Give every new signup a profile row automatically.
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name)
  values (new.id, coalesce(new.raw_user_meta_data->>'name', ''))
  on conflict (id) do nothing;
  return new;
end; $$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============================================================ PHOTO STORAGE
-- Private bucket. Photos are served through short-lived signed URLs, so the
-- files are not publicly browsable.

insert into storage.buckets (id, name, public)
values ('photos', 'photos', false)
on conflict (id) do nothing;

drop policy if exists "own photos read"   on storage.objects;
drop policy if exists "own photos write"  on storage.objects;
drop policy if exists "own photos update" on storage.objects;
drop policy if exists "own photos delete" on storage.objects;

-- Files live at photos/<user-id>/<filename>, so the first path segment
-- decides who may touch them.
create policy "own photos read" on storage.objects
  for select using (
    bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "own photos write" on storage.objects
  for insert with check (
    bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "own photos update" on storage.objects
  for update using (
    bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
  );

create policy "own photos delete" on storage.objects
  for delete using (
    bucket_id = 'photos' and (storage.foldername(name))[1] = auth.uid()::text
  );
