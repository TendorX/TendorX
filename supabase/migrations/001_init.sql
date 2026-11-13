-- TendorX 001_init. Идемпотентно. Только новые объекты. Клиент к таблицам доступа не имеет: чтение каталога через
-- tx_catalog/tx_categories (anon), все записи и роли — только Edge Function api (service_role).
begin;
create table if not exists profiles(tid bigint primary key, name text not null default 'Пользователь', username text,
  role text not null default 'user' check (role in ('user','moderator','support','analyst','admin','master_admin')),
  banned boolean not null default false, created_at timestamptz not null default now(), last_seen timestamptz not null default now());
create table if not exists categories(id serial primary key, slug text unique not null, title text not null, icon text not null default '✦',
  sort int not null default 100, active boolean not null default true, parent_id int references categories(id));
create table if not exists communities(id bigserial primary key, owner_tid bigint not null references profiles(tid),
  username text not null, link text not null, title text not null check (char_length(title) between 2 and 80),
  description text not null default '' check (char_length(description) <= 500),
  kind text not null default 'group' check (kind in ('group','supergroup','channel')),
  category_id int references categories(id), tags text[] not null default '{}',
  status text not null default 'pending' check (status in ('draft','pending','changes','approved','rejected','hidden','blocked')),
  reject_reason text, created_at timestamptz not null default now(), approved_at timestamptz, clicks bigint not null default 0);
create unique index if not exists communities_username_uq on communities(lower(username));
create index if not exists communities_status on communities(status, category_id);
create table if not exists votes(community_id bigint references communities(id) on delete cascade, tid bigint references profiles(tid),
  created_at timestamptz not null default now(), valid boolean not null default true, cancel_reason text, primary key(community_id, tid));
create index if not exists votes_recent on votes(tid, created_at desc);
create table if not exists favorites(community_id bigint references communities(id) on delete cascade, tid bigint references profiles(tid),
  created_at timestamptz not null default now(), primary key(community_id, tid));
create table if not exists notifications(id bigserial primary key, tid bigint not null references profiles(tid), title text not null,
  body text not null default '', created_at timestamptz not null default now());
create index if not exists notifications_tid on notifications(tid, id desc);
create table if not exists settings(key text primary key, value jsonb not null);
create table if not exists audit_log(id bigserial primary key, actor_tid bigint, action text not null, target text, details jsonb,
  created_at timestamptz not null default now());

insert into settings(key, value) values ('votes_per_hour','30'), ('maintenance','false') on conflict do nothing;
insert into categories(slug, title, icon, sort) values ('chat','Общение','💬',10), ('games','Игры','🎮',20), ('business','Бизнес','📈',30),
  ('news','Новости','📰',40), ('tech','Технологии','⚙️',50), ('crypto','Криптовалюта','🪙',60), ('education','Образование','🎓',70),
  ('sport','Спорт','🏅',80), ('fun','Развлечения','🎬',90) on conflict (slug) do nothing;

do $rls$ declare t text; begin
  foreach t in array array['profiles','categories','communities','votes','favorites','notifications','settings','audit_log'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from public, anon, authenticated', t);
    execute format('grant all on table public.%I to service_role', t);
    execute format('drop policy if exists deny_all_client on public.%I', t);
    execute format('create policy deny_all_client on public.%I for all to anon, authenticated using (false) with check (false)', t);
  end loop;
  for t in select pg_get_serial_sequence(format('public.%I', x), 'id') from unnest(array['categories','communities','notifications','audit_log']) x loop
    if t is not null then execute format('revoke all on sequence %s from public, anon, authenticated', t); execute format('grant usage, select, update on sequence %s to service_role', t); end if;
  end loop;
end $rls$;

create or replace function tx_is_staff(p_tid bigint) returns boolean language sql stable security definer set search_path=public, pg_temp as
$$ select coalesce((select role in ('master_admin','admin','moderator','analyst') and not banned from profiles where tid = p_tid), false) $$;

create or replace function tx_categories() returns table(id int, slug text, title text, icon text, groups bigint)
language sql stable security definer set search_path=public, pg_temp as
$$ select c.id, c.slug, c.title, c.icon, (select count(*) from communities m where m.category_id = c.id and m.status = 'approved')
   from categories c where c.active order by c.sort, c.id $$;

-- Органический рейтинг: только валидные голоса. Платных мест нет и они не смешиваются с этим списком.
create or replace function tx_catalog(p_q text default null, p_cat int default null, p_sort text default 'top', p_limit int default 100)
returns table(id bigint, title text, username text, description text, category_id int, category text, tags text[],
  votes bigint, rank bigint, growth bigint, created_at timestamptz)
language sql stable security definer set search_path=public, pg_temp as $$
  with q as (select '%' || replace(replace(replace(trim(coalesce(p_q, '')), '\', '\\'), '%', '\%'), '_', '\_') || '%' as pat),
  v as (select community_id, count(*) filter (where valid) as n, count(*) filter (where valid and created_at > now() - interval '7 days') as g
        from votes group by 1),
  r as (select m.id, m.title, m.username, m.description, m.category_id, m.tags, m.created_at, m.approved_at,
               coalesce(v.n, 0) as votes, coalesce(v.g, 0) as growth,
               rank() over (order by coalesce(v.n, 0) desc, m.approved_at) as rank
        from communities m left join v on v.community_id = m.id where m.status = 'approved')
  select r.id, r.title, r.username, r.description, r.category_id, c.title, r.tags, r.votes, r.rank, r.growth, r.created_at
  from r left join categories c on c.id = r.category_id, q
  where (p_cat is null or r.category_id = p_cat)
    and (nullif(trim(p_q), '') is null or r.title ilike q.pat or r.description ilike q.pat or c.title ilike q.pat
         or exists (select 1 from unnest(r.tags) t where t ilike q.pat))
  order by case p_sort when 'new' then extract(epoch from r.created_at) when 'growth' then r.growth::numeric else r.votes::numeric end desc, r.id
  limit least(greatest(coalesce(p_limit, 100), 1), 200) $$;

create or replace function tx_me(p_tid bigint) returns jsonb language sql stable security definer set search_path=public, pg_temp as $$
  select jsonb_build_object('role', (select role from profiles where tid = p_tid),
   'communities', coalesce((select jsonb_agg(jsonb_build_object('id', m.id, 'title', m.title, 'username', m.username, 'status', m.status,
        'reason', m.reject_reason, 'votes', (select count(*) from votes v where v.community_id = m.id and v.valid), 'clicks', m.clicks) order by m.id desc)
      from communities m where m.owner_tid = p_tid), '[]'::jsonb),
   'favs', coalesce((select jsonb_agg(community_id) from favorites where tid = p_tid), '[]'::jsonb),
   'voted', coalesce((select jsonb_agg(community_id) from votes where tid = p_tid and valid), '[]'::jsonb),
   'notes', coalesce((select jsonb_agg(jsonb_build_object('title', title, 'body', body, 'at', created_at) order by id desc)
      from (select * from notifications where tid = p_tid order by id desc limit 20) n), '[]'::jsonb)) $$;

create or replace function tx_vote(p_tid bigint, p_id bigint) returns jsonb language plpgsql security definer set search_path=public, pg_temp as $$
declare lim int; n int; c communities;
begin
  if coalesce((select banned from profiles where tid = p_tid), true) then raise exception 'Аккаунт ограничен' using errcode = 'TX001'; end if;
  select * into c from communities where id = p_id and status = 'approved';
  if not found then raise exception 'Сообщество недоступно' using errcode = 'TX002'; end if;
  if c.owner_tid = p_tid then raise exception 'Нельзя голосовать за своё сообщество' using errcode = 'TX003'; end if;
  select coalesce((value #>> '{}')::int, 30) into lim from settings where key = 'votes_per_hour';
  select count(*) into n from votes where tid = p_tid and created_at > now() - interval '1 hour';
  if n >= coalesce(lim, 30) then raise exception 'Слишком много голосов за час, попробуйте позже' using errcode = 'TX004'; end if;
  insert into votes(community_id, tid) values (p_id, p_tid) on conflict do nothing;
  get diagnostics n = row_count;
  if n > 0 then insert into notifications(tid, title, body) values (c.owner_tid, 'Новый голос', c.title); end if;
  return jsonb_build_object('added', n > 0, 'votes', (select count(*) from votes where community_id = p_id and valid));
end $$;

create or replace function tx_fav(p_tid bigint, p_id bigint) returns boolean language plpgsql security definer set search_path=public, pg_temp as $$
begin
  if not exists (select 1 from communities where id = p_id and status = 'approved') then raise exception 'Сообщество недоступно' using errcode = 'TX002'; end if;
  delete from favorites where tid = p_tid and community_id = p_id;
  if found then return false; end if;
  insert into favorites(community_id, tid) values (p_id, p_tid); return true;
end $$;

create or replace function tx_click(p_id bigint) returns void language sql security definer set search_path=public, pg_temp as
$$ update communities set clicks = clicks + 1 where id = p_id and status = 'approved' $$;

create or replace function tx_submit(p_tid bigint, p_username text, p_title text, p_desc text, p_cat int, p_tags text[], p_kind text)
returns bigint language plpgsql security definer set search_path=public, pg_temp as $$
declare u text; v bigint;
begin
  if coalesce((select banned from profiles where tid = p_tid), true) then raise exception 'Аккаунт ограничен' using errcode = 'TX001'; end if;
  u := lower(regexp_replace(coalesce(p_username, ''), '^@', ''));
  if u !~ '^[a-z0-9_]{5,32}$' then raise exception 'Ссылка неверная' using errcode = 'TX002'; end if;
  if exists (select 1 from communities where lower(username) = u) then raise exception 'Сообщество уже добавлено' using errcode = 'TX003'; end if;
  if char_length(coalesce(p_title, '')) < 2 or char_length(p_title) > 80 then raise exception 'Название: 2–80 символов' using errcode = 'TX004'; end if;
  if not exists (select 1 from categories where id = p_cat and active) then raise exception 'Выберите категорию' using errcode = 'TX005'; end if;
  if p_kind not in ('group','supergroup','channel') then p_kind := 'group'; end if;
  begin
    insert into communities(owner_tid, username, link, title, description, kind, category_id, tags)
    values (p_tid, u, 'https://t.me/' || u, trim(p_title), left(coalesce(p_desc, ''), 500), p_kind, p_cat, coalesce(p_tags, '{}')) returning id into v;
  exception when unique_violation then raise exception 'Сообщество уже добавлено' using errcode = 'TX003';
  end;
  insert into audit_log(actor_tid, action, target) values (p_tid, 'submit', 'community:' || v);
  return v;
end $$;

create or replace function tx_queue(p_actor bigint) returns jsonb language plpgsql stable security definer set search_path=public, pg_temp as $$
begin
  if not tx_is_staff(p_actor) then raise exception 'Недостаточно прав' using errcode = 'TX403'; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('id', m.id, 'title', m.title, 'username', m.username, 'description', m.description,
      'category', c.title, 'owner', p.name, 'at', m.created_at) order by m.id)
    from communities m left join categories c on c.id = m.category_id left join profiles p on p.tid = m.owner_tid where m.status = 'pending'), '[]'::jsonb);
end $$;

create or replace function tx_stats(p_actor bigint) returns jsonb language plpgsql stable security definer set search_path=public, pg_temp as $$
begin
  if not tx_is_staff(p_actor) then raise exception 'Недостаточно прав' using errcode = 'TX403'; end if;
  return jsonb_build_object('users', (select count(*) from profiles), 'active24h', (select count(*) from profiles where last_seen > now() - interval '24 hours'),
    'banned', (select count(*) from profiles where banned), 'approved', (select count(*) from communities where status = 'approved'),
    'pending', (select count(*) from communities where status = 'pending'), 'votes', (select count(*) from votes where valid),
    'votes24h', (select count(*) from votes where valid and created_at > now() - interval '24 hours'),
    'clicks', (select coalesce(sum(clicks), 0) from communities));
end $$;

create or replace function tx_moderate(p_actor bigint, p_id bigint, p_status text, p_reason text) returns void
language plpgsql security definer set search_path=public, pg_temp as $$
declare m communities;
begin
  if coalesce((select role in ('master_admin','admin','moderator') and not banned from profiles where tid = p_actor), false) is not true then
    raise exception 'Недостаточно прав' using errcode = 'TX403'; end if;
  if p_status not in ('approved','rejected','changes','hidden','blocked') then raise exception 'Неверный статус' using errcode = 'TX004'; end if;
  if p_status in ('rejected','changes','blocked') and char_length(coalesce(trim(p_reason), '')) < 3 then raise exception 'Укажите причину' using errcode = 'TX005'; end if;
  update communities set status = p_status, reject_reason = case when p_status in ('rejected','changes','blocked') then left(trim(p_reason), 300) else null end,
    approved_at = case when p_status = 'approved' then coalesce(approved_at, now()) else approved_at end
  where id = p_id returning * into m;
  if not found then raise exception 'Сообщество не найдено' using errcode = 'TX006'; end if;
  insert into audit_log(actor_tid, action, target, details) values (p_actor, 'moderate', 'community:' || p_id, jsonb_build_object('status', p_status, 'reason', p_reason));
  insert into notifications(tid, title, body) values (m.owner_tid,
    case p_status when 'approved' then 'Сообщество одобрено' when 'rejected' then 'Заявка отклонена' when 'changes' then 'Нужны исправления'
      when 'hidden' then 'Сообщество скрыто' else 'Сообщество заблокировано' end, m.title || coalesce(' — ' || m.reject_reason, ''));
end $$;

do $acl$ declare r record; begin
  for r in select p.oid::regprocedure as s, p.proname as n from pg_proc p join pg_namespace ns on ns.oid = p.pronamespace
           where ns.nspname = 'public' and p.proname like 'tx\_%' loop
    execute format('revoke all on function %s from public, anon, authenticated', r.s);
    execute format('grant execute on function %s to service_role', r.s);
    if r.n in ('tx_categories', 'tx_catalog') then execute format('grant execute on function %s to anon, authenticated', r.s); end if;
  end loop;
end $acl$;
notify pgrst, 'reload schema';
commit;
