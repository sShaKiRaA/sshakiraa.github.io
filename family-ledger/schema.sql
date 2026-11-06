create table public.family_ledger (
user_id uuid primary key references auth.users(id) on delete cascade,
data jsonb not null check (jsonb_typeof(data)='object' and jsonb_typeof(data->'records')='array' and jsonb_typeof(data->'budgets')='object' and octet_length(data::text)<5000000),
revision bigint not null default 1 check(revision>0),
updated_at timestamptz not null default now()
);
alter table public.family_ledger enable row level security;
revoke all on public.family_ledger from anon;
grant select, insert, update on public.family_ledger to authenticated;
create policy ledger_select on public.family_ledger for select to authenticated using ((select auth.uid())=user_id);
create policy ledger_insert on public.family_ledger for insert to authenticated with check ((select auth.uid())=user_id);
create policy ledger_update on public.family_ledger for update to authenticated using ((select auth.uid())=user_id) with check ((select auth.uid())=user_id);
create function public.save_family_ledger(payload jsonb, expected_revision bigint) returns bigint
language plpgsql security invoker set search_path='' as $$
declare result bigint; uid uuid:=auth.uid();
begin
if uid is null then raise exception 'Authentication required'; end if;
if expected_revision=0 then
insert into public.family_ledger(user_id,data,revision) values(uid,payload,1)
on conflict(user_id) do nothing returning revision into result;
else
update public.family_ledger set data=payload, revision=revision+1, updated_at=now()
where user_id=uid and revision=expected_revision returning revision into result;
end if;
if result is null then raise exception 'LEDGER_CONFLICT' using errcode='P0001'; end if;
return result;
end; $$;
revoke all on function public.save_family_ledger(jsonb,bigint) from public, anon;
grant execute on function public.save_family_ledger(jsonb,bigint) to authenticated;
