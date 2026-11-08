create schema if not exists ledger_private;
create table ledger_private.households (
 owner_id uuid primary key references auth.users on delete cascade,
 invited_email text not null,
 member_id uuid unique references auth.users on delete set null,
 check (member_id is distinct from owner_id)
);
create function public.ledger_owner() returns uuid
language sql stable security definer set search_path='' as $$
 select coalesce((select owner_id from ledger_private.households where member_id=auth.uid()),auth.uid())
$$;
create function public.ledger_invite(email text) returns void
language plpgsql security definer set search_path='' as $$
begin
 perform pg_catalog.pg_advisory_xact_lock(81146209);
 if auth.uid() is null or public.ledger_owner() <> auth.uid() then raise exception '仅账本创建者可以邀请'; end if;
 if length(email)>254 or email !~ '^[^[:space:]@]+@[^[:space:]@]+$' then raise exception '请输入有效邮箱'; end if;
 insert into ledger_private.households(owner_id,invited_email) values(auth.uid(),lower(trim(email)))
 on conflict(owner_id) do update set invited_email=excluded.invited_email
 where ledger_private.households.member_id is null;
 if not found then raise exception '该账本已有两位成员'; end if;
end $$;
create function public.ledger_join(owner_email text) returns uuid
language plpgsql security definer set search_path='' as $$
declare target uuid; my_email text;
begin
 perform pg_catalog.pg_advisory_xact_lock(81146209);
 select email into my_email from auth.users where id=auth.uid() and email_confirmed_at is not null;
 if my_email is null or public.ledger_owner() <> auth.uid() or exists(select 1 from ledger_private.households where owner_id=auth.uid() and member_id is not null) then raise exception '当前账号无法加入'; end if;
 update ledger_private.households h set member_id=auth.uid()
 from auth.users u where u.id=h.owner_id and lower(u.email)=lower(trim(owner_email))
 and h.invited_email=lower(my_email) and h.member_id is null and h.owner_id<>auth.uid()
 and not exists(select 1 from ledger_private.households x where x.member_id=h.owner_id)
 returning h.owner_id into target;
 if target is null then raise exception '未找到匹配邀请，请确认双方邮箱'; end if;
 return target;
end $$;
revoke all on function public.ledger_owner(),public.ledger_invite(text),public.ledger_join(text) from public,anon;
grant execute on function public.ledger_owner(),public.ledger_invite(text),public.ledger_join(text) to authenticated;
alter policy ledger_select on public.family_ledger using ((select public.ledger_owner())=user_id);
alter policy ledger_insert on public.family_ledger with check ((select public.ledger_owner())=user_id);
alter policy ledger_update on public.family_ledger using ((select public.ledger_owner())=user_id) with check ((select public.ledger_owner())=user_id);
create function public.save_shared_ledger(payload jsonb, expected_revision bigint, expected_owner uuid) returns bigint
language plpgsql security invoker set search_path='' as $$
declare result bigint; uid uuid:=public.ledger_owner();
begin
if uid is null or uid is distinct from expected_owner then raise exception 'Authentication required'; end if;
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

revoke all on function public.save_shared_ledger(jsonb,bigint,uuid) from public,anon;
grant execute on function public.save_shared_ledger(jsonb,bigint,uuid) to authenticated;
