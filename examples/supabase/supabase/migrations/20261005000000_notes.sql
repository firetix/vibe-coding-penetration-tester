-- Synthetic records for the local example only.
create table public.vpt_notes (
    id uuid primary key,
    owner_id uuid not null references auth.users(id),
    body text not null
);
grant select on public.vpt_notes to anon, authenticated;
alter table public.vpt_notes enable row level security;
create policy owner_reads on public.vpt_notes
    for select to authenticated using ((select auth.uid()) = owner_id);
