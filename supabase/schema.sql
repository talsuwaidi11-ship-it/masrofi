-- مصروفي: cloud schema for Supabase (run once in the SQL editor)
-- Each user sees only the sections they own or that were shared with them.

create table if not exists public.books (
  id text primary key,
  owner uuid not null default auth.uid() references auth.users(id) on delete cascade,
  owner_email text default (auth.jwt() ->> 'email'),
  data jsonb not null default '{}'::jsonb,   -- name, kind, color, budget, contract, contractCat, cats
  updated_at timestamptz not null default now()
);

create table if not exists public.book_members (
  book_id text not null references public.books(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  email text not null,
  role text not null default 'viewer' check (role in ('viewer','editor')),
  primary key (book_id, user_id)
);

create table if not exists public.expenses (
  id text primary key,
  book_id text not null references public.books(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,   -- cat, amount, date, status, method, payee, ref, note, receipt, dueDate, created
  deleted boolean not null default false,
  updated_by uuid default auth.uid(),
  updated_at timestamptz not null default now()
);
create index if not exists expenses_book_idx on public.expenses(book_id, updated_at);
create index if not exists expenses_updated_idx on public.expenses(updated_at);
create index if not exists books_owner_idx on public.books(owner);
create index if not exists book_members_user_idx on public.book_members(user_id);

-- remembers who owned a deleted section, so nobody else can take over its id (and its old receipt photos)
create table if not exists public.deleted_books (
  id text primary key,
  owner uuid not null
);
alter table public.deleted_books enable row level security;
revoke all on public.deleted_books from anon, authenticated;

create or replace function public.touch() returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;
drop trigger if exists books_touch on public.books;
create trigger books_touch before update on public.books for each row execute function public.touch();
drop trigger if exists expenses_touch on public.expenses;
create or replace function public.touch_expense() returns trigger language plpgsql as $$
begin new.updated_at = now(); new.updated_by = auth.uid(); return new; end $$;
create trigger expenses_touch before insert or update on public.expenses for each row execute function public.touch_expense();

-- owner and owner_email always come from the signed-in user, never from the client
create or replace function public.books_owner() returns trigger language plpgsql as $$
begin
  if tg_op = 'INSERT' then
    new.owner = auth.uid(); new.owner_email = auth.jwt() ->> 'email';
  else
    new.owner = old.owner; new.owner_email = old.owner_email;
  end if;
  return new;
end $$;
drop trigger if exists books_owner on public.books;
create trigger books_owner before insert or update on public.books for each row execute function public.books_owner();

-- access helpers (security definer so policies don't recurse)
create or replace function public.can_read(b text) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists(select 1 from public.books where id = b and owner = auth.uid())
      or exists(select 1 from public.book_members where book_id = b and user_id = auth.uid())
$$;
create or replace function public.can_write(b text) returns boolean
language sql security definer stable set search_path = '' as $$
  select exists(select 1 from public.books where id = b and owner = auth.uid())
      or exists(select 1 from public.book_members where book_id = b and user_id = auth.uid() and role = 'editor')
$$;
create or replace function public.id_free(b text) returns boolean
language sql security definer stable set search_path = '' as $$
  select not exists(select 1 from public.deleted_books where id = b and owner <> auth.uid())
$$;
create or replace function public.books_tombstone() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.deleted_books(id, owner) values (old.id, old.owner)
    on conflict (id) do update set owner = excluded.owner;
  return old;
end $$;
drop trigger if exists books_tombstone on public.books;
create trigger books_tombstone after delete on public.books for each row execute function public.books_tombstone();

alter table public.books enable row level security;
alter table public.book_members enable row level security;
alter table public.expenses enable row level security;

drop policy if exists books_select on public.books;
create policy books_select on public.books for select using (owner = auth.uid() or public.can_read(id));
drop policy if exists books_insert on public.books;
create policy books_insert on public.books for insert with check (owner = auth.uid() and public.id_free(id));
drop policy if exists books_update on public.books;
create policy books_update on public.books for update using (public.can_write(id)) with check (public.can_write(id));
drop policy if exists books_delete on public.books;
create policy books_delete on public.books for delete using (owner = auth.uid());

-- everyone in a section can see who else is in it
drop policy if exists members_select on public.book_members;
create policy members_select on public.book_members for select
  using (user_id = auth.uid() or public.can_read(book_id));
-- the owner can change a member's role (and only the role)
drop policy if exists members_update on public.book_members;
create policy members_update on public.book_members for update
  using (exists(select 1 from public.books where id = book_id and owner = auth.uid()))
  with check (exists(select 1 from public.books where id = book_id and owner = auth.uid()));
revoke update on public.book_members from anon, authenticated;
grant update (role) on public.book_members to authenticated;
drop policy if exists members_delete on public.book_members;
create policy members_delete on public.book_members for delete
  using (user_id = auth.uid() or exists(select 1 from public.books where id = book_id and owner = auth.uid()));
-- inserts go through share_book() only

drop policy if exists expenses_select on public.expenses;
create policy expenses_select on public.expenses for select using (public.can_read(book_id));
drop policy if exists expenses_insert on public.expenses;
create policy expenses_insert on public.expenses for insert with check (public.can_write(book_id));
drop policy if exists expenses_update on public.expenses;
create policy expenses_update on public.expenses for update using (public.can_write(book_id)) with check (public.can_write(book_id));

-- owner shares a section with someone who already has an account
create or replace function public.share_book(b text, member_email text, member_role text default 'viewer')
returns text language plpgsql security definer set search_path = '' as $$
declare uid uuid;
begin
  if not exists(select 1 from public.books where id = b and owner = auth.uid()) then
    raise exception 'not_owner';
  end if;
  if member_role not in ('viewer','editor') then raise exception 'bad_role'; end if;
  select id into uid from auth.users where lower(email) = lower(trim(member_email));
  if uid is null then return 'no_account'; end if;
  if uid = auth.uid() then return 'self'; end if;
  insert into public.book_members(book_id, user_id, email, role) values (b, uid, lower(trim(member_email)), member_role)
    on conflict (book_id, user_id) do update set role = excluded.role;
  return 'ok';
end $$;
revoke all on function public.share_book(text,text,text) from public, anon;
grant execute on function public.share_book(text,text,text) to authenticated;

-- invite links: the owner makes a one-time link (7 days); whoever opens it signed in joins the section
create table if not exists public.invites (
  token text primary key default replace(gen_random_uuid()::text, '-', ''),
  book_id text not null references public.books(id) on delete cascade,
  role text not null default 'viewer' check (role in ('viewer','editor')),
  created_by uuid not null default auth.uid(),
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '7 days',
  used_by uuid,
  used_at timestamptz
);
create index if not exists invites_book_idx on public.invites(book_id);
alter table public.invites enable row level security;
revoke insert, update on public.invites from anon, authenticated;
drop policy if exists invites_select on public.invites;
create policy invites_select on public.invites for select
  using (exists(select 1 from public.books where id = book_id and owner = auth.uid()));
drop policy if exists invites_delete on public.invites;
create policy invites_delete on public.invites for delete
  using (exists(select 1 from public.books where id = book_id and owner = auth.uid()));

create or replace function public.create_invite(b text, member_role text default 'viewer')
returns text language plpgsql security definer set search_path = '' as $$
declare t text;
begin
  if not exists(select 1 from public.books where id = b and owner = auth.uid()) then
    raise exception 'not_owner';
  end if;
  if member_role not in ('viewer','editor') then raise exception 'bad_role'; end if;
  if (select count(*) from public.invites where book_id = b and used_at is null and expires_at > now()) >= 20 then
    raise exception 'too_many';
  end if;
  delete from public.invites where book_id = b and (used_at is not null or expires_at < now() - interval '30 days');
  insert into public.invites(book_id, role, created_by) values (b, member_role, auth.uid()) returning token into t;
  return t;
end $$;

-- what an invite is for, so the sign-in page can say who invited you (only whoever holds the link can ask)
create or replace function public.invite_info(t text)
returns json language sql security definer stable set search_path = '' as $$
  select json_build_object('name', b.data ->> 'name', 'from', b.owner_email, 'role', i.role,
    's', case when i.used_at is not null then 'used' when i.expires_at < now() then 'expired' else 'ok' end)
  from public.invites i join public.books b on b.id = i.book_id
  where i.token = t
$$;

create or replace function public.accept_invite(t text)
returns json language plpgsql security definer set search_path = '' as $$
declare i public.invites; bk public.books; em text := lower(coalesce(auth.jwt() ->> 'email', ''));
begin
  if auth.uid() is null then raise exception 'not_signed_in'; end if;
  select * into i from public.invites where token = t for update;
  if not found then return json_build_object('s','invalid'); end if;
  select * into bk from public.books where id = i.book_id;
  if bk.owner = auth.uid() then return json_build_object('s','self','b',bk.id,'n',bk.data ->> 'name'); end if;
  if i.used_at is not null then
    if i.used_by = auth.uid() then return json_build_object('s','ok','b',bk.id,'n',bk.data ->> 'name'); end if;
    return json_build_object('s','used');
  end if;
  if i.expires_at < now() then return json_build_object('s','expired'); end if;
  insert into public.book_members(book_id, user_id, email, role) values (i.book_id, auth.uid(), em, i.role)
    on conflict (book_id, user_id) do update
      set role = case when public.book_members.role = 'editor' then 'editor' else excluded.role end;
  update public.invites set used_by = auth.uid(), used_at = now() where token = t;
  return json_build_object('s','ok','b',bk.id,'n',bk.data ->> 'name');
end $$;
revoke all on function public.create_invite(text,text) from public, anon;
revoke all on function public.accept_invite(text) from public, anon;
revoke all on function public.invite_info(text) from public;
grant execute on function public.create_invite(text,text) to authenticated;
grant execute on function public.accept_invite(text) to authenticated;
grant execute on function public.invite_info(text) to anon, authenticated;

-- receipt photos: private bucket, path = <book_id>/<expense_id>.jpg
insert into storage.buckets (id, name, public) values ('receipts','receipts', false)
  on conflict (id) do nothing;
drop policy if exists receipts_read on storage.objects;
create policy receipts_read on storage.objects for select
  using (bucket_id = 'receipts' and public.can_read(split_part(name,'/',1)));
drop policy if exists receipts_write on storage.objects;
create policy receipts_write on storage.objects for insert
  with check (bucket_id = 'receipts' and public.can_write(split_part(name,'/',1)));
drop policy if exists receipts_update on storage.objects;
create policy receipts_update on storage.objects for update
  using (bucket_id = 'receipts' and public.can_write(split_part(name,'/',1)));
drop policy if exists receipts_delete on storage.objects;
create policy receipts_delete on storage.objects for delete
  using (bucket_id = 'receipts' and public.can_write(split_part(name,'/',1)));
